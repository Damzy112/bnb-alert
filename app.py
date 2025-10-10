import os
import time
import asyncio
import requests
import json
import threading
import re
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
import logging
from fastapi import FastAPI, Request, HTTPException

# ---------------------------
# Config & env load
# ---------------------------
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_IDS")
MORALIS_API_KEY = os.getenv("MORALIS_API_KEY")

# Background config
MC_CHECK_INTERVAL = int(os.getenv("MC_CHECK_INTERVAL", "600"))  # seconds between market-cap checks (default 10 minutes)
HONEYPOT_SAMPLE_LIMIT = int(os.getenv("HONEYPOT_SAMPLE_LIMIT", "50"))
DEXSCREENER_CACHE_TTL = int(os.getenv("DEXSCREENER_CACHE_TTL", "60"))  # seconds
TELEGRAM_POLL_INTERVAL = int(os.getenv("TELEGRAM_POLL_INTERVAL", "3"))  # seconds for getUpdates polling

if TELEGRAM_CHAT_IDS:
    TELEGRAM_CHAT_IDS = [chat_id.strip() for chat_id in TELEGRAM_CHAT_IDS.split(",")]

required_vars = {
    "TELEGRAM_BOT_TOKEN": TELEGRAM_BOT_TOKEN,
    "TELEGRAM_CHAT_IDS": TELEGRAM_CHAT_IDS,
    "MORALIS_API_KEY": MORALIS_API_KEY,
}
missing = [k for k, v in required_vars.items() if not v]
if missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")

# ---------------------------
# Logging (stdout + file)
# ---------------------------
LOG_FILE = "bot.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ],
)
logger = logging.getLogger("bnb_webhook_monitor")

def log(msg):
    logger.info(msg)

# ---------------------------
# Watchlist & aliases
# ---------------------------
WALLETS = {
    w.lower() for w in [
        "0x749Ee34445f470d8Bdf1A14a79367408B29d579B",
        "0xFDE09A5f5DB264bA7261D25E24EB930d67a87b28",
        "0x65B904285B1c9aB3f6d348446d8c0cEA5b4AeD25",
        "0x9FcA0F07D2F36B76990DA744C86D4991efEa9C20",
        "0xA8fCc482f8e04A0D9C4e11f18Fee714f48EdA4b4",
    ]
}

WALLET_ALIASES = {
    "0x749Ee34445f470d8Bdf1A14a79367408B29d579B".lower(): "Alaba",
    "0xFDE09A5f5DB264bA7261D25E24EB930d67a87b28".lower(): "Benjamin",
    "0x65B904285B1c9aB3f6d348446d8c0cEA5b4AeD25".lower(): "Caro",
    "0x9FcA0F07D2F36B76990DA744C86D4991efEa9C20".lower(): "Dolapo",
    "0xA8fCc482f8e04A0D9C4e11f18Fee714f48EdA4b4".lower(): "Ezekiel"
}

# ---------------------------
# Blacklist system (token addresses lowercased)
# ---------------------------
BLACKLIST_FILE = "blacklist_bnb.json"

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set([x.lower() for x in json.load(f)])
    except Exception:
        return set()

def save_blacklist(s):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(list(s), f)

blacklisted_tokens = load_blacklist()

# ---------------------------
# Globals (in-memory)
# ---------------------------
seen_transactions = set()            # dedupe tx hashes
token_to_wallets = defaultdict(set)  # token -> set(watched wallets that bought)
wallet_buy_times = {}                 # (token,wallet) -> timestamp
token_tracking = {}                   # token -> {'state','initial_mc','first_time'}
metadata_cache = {}                   # token -> (name,symbol,price,market_cap,ts)
honeypot_cache = {}                   # token -> (is_honeypot_bool, checked_at)
dex_cache = {}                        # token -> (raw_pairs, ts)

# Router heuristics (lowercased)
KNOWN_ROUTER_ADDRESSES = {
    "0x10ed43c718714eb63d5aa57b78b54704e256024e",  # PancakeSwap v2
}
# Ignored tokens
IGNORED_TOKENS = {
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56",
    "0x55d398326f99059ff775485246999027b3197955",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
}
IGNORED_TOKENS = {t.lower() for t in IGNORED_TOKENS}

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="BNB Moralis Webhook Monitor")

# ---------------------------
# Telegram helper
# ---------------------------
def send_telegram_alert(message: str):
    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown", "disable_web_page_preview": False}
            r = requests.post(url, data=data, timeout=10)
            if r.status_code != 200:
                log(f"⚠️ Telegram send failed ({r.status_code}): {r.text[:200]}")
        except Exception as e:
            log(f"⚠️ Telegram send exception: {e}")

# ---------------------------
# Utility: dex metadata (Dexscreener) - cached
# returns (name, symbol, price, market_cap)
# market_cap uses 'fdv' if available
# ---------------------------
def get_token_metadata(token_address: str):
    token_address = token_address.lower()
    now = time.time()
    if token_address in metadata_cache:
        name, symbol, price, mc, ts = metadata_cache[token_address]
        if now - ts < DEXSCREENER_CACHE_TTL:
            return name, symbol, price, mc

    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            log(f"⚠️ Dexscreener fetch failed ({r.status_code}) for {token_address}")
            name, symbol, price, mc = "Unknown", "", "N/A", "N/A"
        else:
            pairs = r.json().get("pairs", []) or []
            if pairs:
                p = pairs[0]
                name = p.get("baseToken", {}).get("name", "Unknown")
                symbol = p.get("baseToken", {}).get("symbol", "")
                price = p.get("priceUsd", "N/A")
                mc = p.get("fdv", "N/A")
            else:
                name, symbol, price, mc = "Unknown", "", "N/A", "N/A"
    except Exception as e:
        log(f"⚠️ Dexscreener exception for {token_address}: {e}")
        name, symbol, price, mc = "Unknown", "", "N/A", "N/A"

    metadata_cache[token_address] = (name, symbol, price, mc, now)
    return name, symbol, price, mc

# ---------------------------
# Honeypot heuristic (cached)
# - Check Dexscreener pairs (if none -> suspicious)
# - Fetch recent contract transfers via Moralis and look for sells to router/pair addresses
# ---------------------------
def is_honeypot(token_address: str, sample_limit: int = HONEYPOT_SAMPLE_LIMIT):
    token_address = token_address.lower()
    now = time.time()
    if token_address in honeypot_cache:
        res, checked_at = honeypot_cache[token_address]
        if now - checked_at < HONEYPOT_TTL:
            return res

    log(f"🔎 Honeypot check for {token_address} ...")

    # 1) Dexscreener pairs
    try:
        r = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{token_address}", timeout=8)
        pairs = r.json().get("pairs", []) if r.status_code == 200 else []
    except Exception as e:
        log(f"⚠️ Dexscreener error during honeypot check: {e}")
        pairs = []

    if not pairs:
        honeypot_cache[token_address] = (True, now)
        log(f"⚠️ No pair on Dexscreener => flagged as honeypot: {token_address}")
        return True

    pair_addresses = set()
    for pair in pairs:
        pair_addr = pair.get("pairAddress") or (pair.get("pair") or {}).get("address")
        if pair_addr:
            pair_addresses.add(pair_addr.lower())

    # 2) Recent transfers for token (Moralis)
    sells_found = False
    try:
        url = f"https://deep-index.moralis.io/api/v2.2/erc20/{token_address}/transfers?chain=bsc&limit={sample_limit}"
        headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 200:
            data = r.json()
            transfers = data.get("result", []) if isinstance(data, dict) else []
            for t in transfers:
                to_addr = (t.get("to_address") or "").lower()
                if to_addr in KNOWN_ROUTER_ADDRESSES or to_addr in pair_addresses:
                    sells_found = True
                    break
        else:
            log(f"⚠️ Moralis token transfers fetch failed ({r.status_code}) during honeypot check")
    except Exception as e:
        log(f"⚠️ Moralis honeypot fetch exception: {e}")

    is_hp = not sells_found
    honeypot_cache[token_address] = (is_hp, now)
    if is_hp:
        log(f"⚠️ Honeypot heuristic: {token_address} flagged as possible honeypot (no sells found).")
    else:
        log(f"✅ Honeypot heuristic: {token_address} appears sellable (sells found).")
    return is_hp

# ---------------------------
# Heuristic: is sell tx? (based on tx payload keys we receive)
# We'll consider to-address in known routers or to pair addresses as sells
# ---------------------------
def is_sell_tx_from_payload(tx_dict: dict):
    to_addr = (tx_dict.get("to") or tx_dict.get("to_address") or tx_dict.get("toAddress") or "").lower()
    if not to_addr:
        return False
    if to_addr in KNOWN_ROUTER_ADDRESSES:
        return True
    # Additional pair heuristics could be added here
    return False

# ---------------------------
# Process a single transfer event (bought or sold)
# Mimics earlier polling logic but triggered by webhook event
# ---------------------------
def handle_transfer_event(tx):
    """
    Expected tx dict fields (flexible):
    - transaction_hash / transactionHash / hash
    - address / token / contractAddress -> token contract
    - from / from_address / fromAddress
    - to / to_address / toAddress
    - token_symbol / tokenSymbol / symbol
    """
    try:
        # normalize fields
        tx_hash = tx.get("transaction_hash") or tx.get("transactionHash") or tx.get("hash") or tx.get("tx_hash")
        token_address = (tx.get("address") or tx.get("token") or tx.get("contractAddress") or "").lower()
        from_addr = (tx.get("from_address") or tx.get("from") or tx.get("fromAddress") or "").lower()
        to_addr = (tx.get("to_address") or tx.get("to") or tx.get("toAddress") or "").lower()
        symbol = tx.get("token_symbol") or tx.get("tokenSymbol") or tx.get("symbol") or ""

        if not tx_hash or not token_address:
            log(f"   ↪ Skipping payload missing essential fields: {tx_hash}, {token_address}")
            return

        if tx_hash in seen_transactions:
            log(f"   ↪ Duplicate tx {tx_hash} ignored")
            return
        seen_transactions.add(tx_hash)

        # skip ignored/blacklisted tokens
        if token_address in IGNORED_TOKENS or token_address in blacklisted_tokens:
            log(f"   ↪ Ignored or blacklisted token {token_address} (tx {tx_hash})")
            return

        # SELL detection (outgoing from watched wallet)
        if from_addr in WALLETS and is_sell_tx_from_payload(tx):
            alias = WALLET_ALIASES.get(from_addr, from_addr)
            name, symbol_m, price, mc = get_token_metadata(token_address)
            msg = (
                f"⚠️ *Sell Alert*\n"
                f"{alias} sold token:\n\n"
                f"🔹 Token: *{name}* (`{symbol_m or symbol}`)\n"
                f"💲 Price: `${price}`\n"
                f"📊 Market Cap: `${mc}`\n"
                f"🪙 Address: `{token_address}`\n"
                f"🔁 Tx: `{tx_hash}`\n"
            )
            send_telegram_alert(msg)
            log(f"   ↪ Sent sell alert for {token_address} by {alias}")
            return

        # BUY detection (incoming to watched wallet)
        if to_addr in WALLETS:
            watcher = to_addr
            token_to_wallets[token_address].add(watcher)
            key = (token_address, watcher)
            if key not in wallet_buy_times:
                wallet_buy_times[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log(f"   ↪ {WALLET_ALIASES.get(watcher, watcher)} received {token_address} (tx {tx_hash})")

            # If >= 2 watched wallets bought -> begin/continue tracking
            if len(token_to_wallets[token_address]) >= 2:
                # do not track if previously stopped
                tk_state = token_tracking.get(token_address, {}).get("state")
                if tk_state == "stopped":
                    log(f"   ↪ Token {token_address} previously stopped; skipping.")
                    return

                # if not yet tracking, set initial MC
                if token_address not in token_tracking or token_tracking[token_address].get("state") is None:
                    name, symbol_m, price, mc = get_token_metadata(token_address)
                    try:
                        initial_mc = float(mc)
                    except Exception:
                        initial_mc = None

                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                    token_tracking[token_address] = {
                        "state": "tracking",
                        "initial_mc": initial_mc,
                        "first_time": now_str
                    }
                    if initial_mc is not None:
                        log(f"   ↪ Started tracking {token_address} with initial MC {initial_mc} at {now_str}")
                    else:
                        log(f"   ↪ Started tracking {token_address} with unknown initial MC at {now_str}")

                # now evaluate immediate conditions (honeypot + thresholds)
                tracking = token_tracking.get(token_address, {})
                if tracking.get("state") == "tracking":
                    # Honeypot check (conservative)
                    try:
                        hp = is_honeypot(token_address)
                    except Exception as e:
                        log(f"   ↪ Honeypot check error for {token_address}: {e}")
                        hp = True  # be conservative if error

                    if hp:
                        log(f"   ↪ {token_address} flagged as honeypot — will NOT alert and will stop tracking.")
                        token_tracking[token_address] = {"state": "stopped"}
                        return

                    # immediate market cap check via Dexscreener
                    name, symbol_m, price, mc = get_token_metadata(token_address)
                    try:
                        current_mc = float(mc)
                    except Exception:
                        current_mc = None

                    initial_mc = tracking.get("initial_mc")
                    if initial_mc is None and current_mc is not None:
                        token_tracking[token_address]["initial_mc"] = current_mc
                        token_tracking[token_address]["first_time"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                        initial_mc = current_mc
                        log(f"   ↪ Set initial MC for {token_address} to {initial_mc}")

                    if initial_mc is not None and current_mc is not None:
                        # stop if dropped <80%
                        if current_mc < 0.8 * initial_mc:
                            token_tracking[token_address] = {"state": "stopped"}
                            log(f"   ↪ Stopped tracking {token_address} because MC dropped below 80% ({current_mc} < 0.8*{initial_mc})")
                            return

                        # alert if >= 3x initial
                        if current_mc >= 3.0 * initial_mc and token_tracking[token_address].get("state") == "tracking":
                            wallets_sorted = sorted(token_to_wallets[token_address], key=lambda w: wallet_buy_times.get((token_address, w), ""))
                            wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                            pct = ((current_mc - initial_mc) / initial_mc) * 100
                            msg = (
                                f"🚨 *BNB Token BIG MOVE!* 🚀\n"
                                f"*{len(token_to_wallets[token_address])} watched wallets* bought this token and market cap is up +200%:\n\n"
                                f"🔹 Token: *{name}* (`{symbol_m}`)\n"
                                f"💲 Price: `${price}`\n"
                                f"📊 Market Cap: `${mc}`\n"
                                f"🟩 *Return Since First Alert:* +{pct:.2f}%\n"
                                f"📅 First Alert: {token_tracking[token_address].get('first_time')}\n"
                                f"📅 Now: {now_str}\n"
                                f"🪙 Address: `{token_address}`\n\n"
                                f"👛 Wallets (by time bought):\n{wallet_list}\n\n"
                                f"[🔎 View on Dexscreener](https://dexscreener.com/bsc/{token_address}) | [🐦 Search on Twitter](https://twitter.com/search?q={token_address})"
                            )
                            send_telegram_alert(msg)
                            log(f"   ↪ Sent +200% alert for {token_address}")
                            token_tracking[token_address]["state"] = "alerted"
                    else:
                        log(f"   ↪ Unable to evaluate MC thresholds for {token_address} (initial:{initial_mc}, current:{current_mc})")
    except Exception as e:
        log(f"⚠️ Exception in handle_transfer_event: {e}")

# ---------------------------
# Extract transfers from Moralis webhook payload
# Moralis stream payload structure varies; we make this flexible:
# - Look for lists of objects with token-like keys
# - Support arrays under top-level keys like 'events', 'result', 'erc20Transfers', etc.
# ---------------------------
def extract_transfer_objects(payload):
    transfers = []

    if isinstance(payload, dict):
        # Common keys
        for key in ("erc20Transfers", "tokenTransfers", "result", "events", "logs", "transfers"):
            val = payload.get(key)
            if isinstance(val, list):
                transfers.extend(val)

        # Some payload formats have nested 'payload' or 'event' fields
        # recursively inspect values for dictionaries/lists that look like transfers
        def _scan(obj):
            if isinstance(obj, dict):
                # heuristic check
                if ("transaction_hash" in obj) or ("from_address" in obj and "to_address" in obj) or ("address" in obj and "to_address" in obj):
                    transfers.append(obj)
                else:
                    for v in obj.values():
                        _scan(v)
            elif isinstance(obj, list):
                for item in obj:
                    _scan(item)

        _scan(payload)

    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                if ("transaction_hash" in item) or ("from_address" in item and "to_address" in item):
                    transfers.append(item)

    # as a last resort, if payload contains top-level fields resembling a single transfer, append payload itself
    if not transfers and isinstance(payload, dict):
        if ("transaction_hash" in payload) or ("from_address" in payload and "to_address" in payload):
            transfers.append(payload)

    return transfers

# ---------------------------
# Webhook endpoint for Moralis Stream
# ---------------------------
@app.post("/webhook")
async def webhook(request: Request):
    """
    Moralis will POST event payloads here.
    We accept flexible payload formats and extract transfer objects.
    """
    try:
        payload = await request.json()
    except Exception as e:
        log(f"⚠️ Failed to parse JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # quick health/log
    log(f"📥 Received webhook payload: keys={list(payload.keys()) if isinstance(payload, dict) else 'list'}")

    transfers = extract_transfer_objects(payload)
    if not transfers:
        log("   ↪ No transfer objects found in payload")
        # return 200 quickly so Moralis verifies success
        return {"status": "ok", "processed": 0}

    processed = 0
    # process transfers asynchronously but without blocking response
    for t in transfers:
        threading.Thread(target=handle_transfer_event, args=(t,), daemon=True).start()
        processed += 1

    # return quickly to Moralis so it gets HTTP 200
    return {"status": "ok", "processed": processed}

# ---------------------------
# Telegram blacklist listener (background thread)
# - Allows admins (in TELEGRAM_CHAT_IDS) to send a contract address to blacklist
# ---------------------------
def telegram_blacklist_listener():
    log("📨 Telegram blacklist listener started")
    offset = None
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"timeout": 30}
            if offset:
                params["offset"] = offset
            res = requests.get(url, params=params, timeout=35)
            data = res.json()
            for update in data.get("result", []):
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = (msg.get("text") or "").strip()
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if chat_id not in TELEGRAM_CHAT_IDS:
                    continue
                if re.fullmatch(r"0x[a-fA-F0-9]{40}", text):
                    addr = text.lower()
                    if addr in blacklisted_tokens:
                        send_telegram_alert(f"⚠️ Token already blacklisted:\n`{text}`")
                    else:
                        blacklisted_tokens.add(addr)
                        save_blacklist(blacklisted_tokens)
                        send_telegram_alert(f"✅ Token blacklisted:\n`{text}`")
                        log(f"   ↪ Token {addr} added to blacklist via Telegram")
        except Exception as e:
            log(f"⚠️ Telegram listener error: {e}")
        time.sleep(TELEGRAM_POLL_INTERVAL)

# ---------------------------
# Background coroutine: periodically check market cap for tracked tokens
# - Only runs for tokens in token_tracking with state 'tracking'
# - Uses Dexscreener for market cap (cheap)
# ---------------------------
async def periodic_mc_checker():
    while True:
        try:
            tracked = [tk for tk, info in token_tracking.items() if info.get("state") == "tracking"]
            if tracked:
                log(f"🔁 MC checker: re-evaluating {len(tracked)} tracked tokens")
            for token in tracked:
                try:
                    name, symbol, price, mc = get_token_metadata(token)
                    try:
                        current_mc = float(mc)
                    except Exception:
                        current_mc = None
                    initial = token_tracking[token].get("initial_mc")
                    if initial is None and current_mc is not None:
                        token_tracking[token]["initial_mc"] = current_mc
                        token_tracking[token]["first_time"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                        initial = current_mc
                        log(f"   ↪ Set initial MC for {token} to {initial} during periodic check")

                    if initial is not None and current_mc is not None:
                        # drop below 80%
                        if current_mc < 0.8 * initial:
                            token_tracking[token] = {"state": "stopped"}
                            log(f"   ↪ Stopped tracking {token} because MC dropped below 80% ({current_mc} < 0.8*{initial})")
                            continue
                        # alert >= 3x
                        if current_mc >= 3.0 * initial and token_tracking[token].get("state") == "tracking":
                            wallets_sorted = sorted(token_to_wallets[token], key=lambda w: wallet_buy_times.get((token, w), ""))
                            wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                            pct = ((current_mc - initial) / initial) * 100
                            msg = (
                                f"🚨 *BNB Token BIG MOVE!* 🚀\n"
                                f"*{len(token_to_wallets[token])} watched wallets* bought this token and market cap is up +200%:\n\n"
                                f"🔹 Token: *{name}* (`{symbol}`)\n"
                                f"💲 Price: `${price}`\n"
                                f"📊 Market Cap: `${mc}`\n"
                                f"🟩 *Return Since First Alert:* +{pct:.2f}%\n"
                                f"📅 First Alert: {token_tracking[token].get('first_time')}\n"
                                f"📅 Now: {now_str}\n"
                                f"🪙 Address: `{token}`\n\n"
                                f"👛 Wallets (by time bought):\n{wallet_list}\n\n"
                                f"[🔎 View on Dexscreener](https://dexscreener.com/bsc/{token}) | [🐦 Search on Twitter](https://twitter.com/search?q={token})"
                            )
                            send_telegram_alert(msg)
                            log(f"   ↪ Sent +200% periodic alert for {token}")
                            token_tracking[token]["state"] = "alerted"
                except Exception as e:
                    log(f"⚠️ Error during periodic MC check for {token}: {e}")
            # sleep for configured interval
            await asyncio.sleep(MC_CHECK_INTERVAL)
        except Exception as e:
            log(f"⚠️ periodic_mc_checker crashed: {e}")
            await asyncio.sleep(30)

# ---------------------------
# Startup event: launch periodic checker + telegram listener thread
# ---------------------------
@app.on_event("startup")
async def startup_event():
    log("🚀 App starting up - launching background tasks")
    loop = asyncio.get_event_loop()
    loop.create_task(periodic_mc_checker())
    # start telegram listener in background thread
    t = threading.Thread(target=telegram_blacklist_listener, daemon=True)
    t.start()

# ---------------------------
# Simple health endpoint
# ---------------------------
@app.get("/health")
def health():
    return {"status": "ok", "tracked_tokens": len(token_tracking), "seen_tx": len(seen_transactions)}

# ---------------------------
# Run info (if executed directly, uvicorn will be used by Procfile in deployment)
# ---------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
