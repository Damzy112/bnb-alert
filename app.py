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
# ---------------------------
def is_honeypot(token_address: str, sample_limit: int = HONEYPOT_SAMPLE_LIMIT):
    token_address = token_address.lower()
    now = time.time()
    if token_address in honeypot_cache:
        res, checked_at = honeypot_cache[token_address]
        if now - checked_at < HONEYPOT_CACHE_TTL:
            return res

    log(f"🔎 Honeypot check for {token_address} ...")

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
# Heuristic: is sell tx?
# ---------------------------
def is_sell_tx_from_payload(tx_dict: dict):
    to_addr = (tx_dict.get("to") or tx_dict.get("to_address") or tx_dict.get("toAddress") or "").lower()
    if not to_addr:
        return False
    if to_addr in KNOWN_ROUTER_ADDRESSES:
        return True
    return False

# ---------------------------
# Handle transfer event
# ---------------------------
def handle_transfer_event(tx):
    try:
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

        if token_address in IGNORED_TOKENS or token_address in blacklisted_tokens:
            log(f"   ↪ Ignored or blacklisted token {token_address} (tx {tx_hash})")
            return

        # SELL detection
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
            log(f"   ↪ Sent sell alert for {token_address}")
            return

        # BUY detection
        if to_addr in WALLETS:
            watcher = to_addr
            token_to_wallets[token_address].add(watcher)
            key = (token_address, watcher)
            if key not in wallet_buy_times:
                wallet_buy_times[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log(f"   ↪ {WALLET_ALIASES.get(watcher, watcher)} received {token_address} (tx {tx_hash})")

            # >=2 wallets bought -> tracking
            if len(token_to_wallets[token_address]) >= 2:
                tk_state = token_tracking.get(token_address, {}).get("state")
                if tk_state == "stopped":
                    log(f"   ↪ Token {token_address} previously stopped; skipping.")
                    return

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
                    log(f"   ↪ Started tracking {token_address} with initial MC {initial_mc}")

                tracking = token_tracking.get(token_address, {})
                if tracking.get("state") == "tracking":
                    try:
                        hp = is_honeypot(token_address)
                    except Exception as e:
                        log(f"   ↪ Honeypot check error for {token_address}: {e}")
                        hp = True
                    if hp:
                        log(f"   ↪ {token_address} flagged as honeypot — stopping tracking.")
                        token_tracking[token_address] = {"state": "stopped"}
                        return

                    # update MC & stop if dropped <80%
                    name, symbol_m, price, mc = get_token_metadata(token_address)
                    try:
                        current_mc = float(mc)
                    except Exception:
                        current_mc = None

                    initial_mc = tracking.get("initial_mc")
                    if initial_mc is None and current_mc is not None:
                        token_tracking[token_address]["initial_mc"] = current_mc
                        token_tracking[token_address]["first_time"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                        log(f"   ↪ Set initial MC for {token_address} to {current_mc}")

                    if initial_mc is not None and current_mc is not None and current_mc < 0.8 * initial_mc:
                        token_tracking[token_address] = {"state": "stopped"}
                        log(f"   ↪ Stopped tracking {token_address} because MC dropped below 80% ({current_mc} < 0.8*{initial_mc})")

    except Exception as e:
        log(f"⚠️ Exception in handle_transfer_event: {e}")

# ---------------------------
# Extract transfers from Moralis webhook payload
# ---------------------------
def extract_transfer_objects(payload):
    transfers = []

    if isinstance(payload, dict):
        for key in ("erc20Transfers", "tokenTransfers", "result", "events", "logs", "transfers"):
            val = payload.get(key)
            if isinstance(val, list):
                transfers.extend(val)

        def _scan(obj):
            if isinstance(obj, dict):
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

    if not transfers and isinstance(payload, dict):
        if ("transaction_hash" in payload) or ("from_address" in payload and "to_address" in payload):
            transfers.append(payload)

    return transfers

# ---------------------------
# Webhook endpoint
# ---------------------------
@app.post("/webhook")
async def webhook(request: Request):
    try:
        payload = await request.json()
    except Exception as e:
        log(f"⚠️ Invalid JSON in webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    transfers = extract_transfer_objects(payload)
    if not transfers:
        log("⚠️ Webhook received but no transfers found")
        return {"status": "ignored"}

    for tx in transfers:
        handle_transfer_event(tx)
    return {"status": "processed", "count": len(transfers)}

# ---------------------------
# Periodic market-cap checker (optional)
# ---------------------------
def periodic_mc_checker():
    while True:
        try:
            for token, tracking in token_tracking.items():
                if tracking.get("state") != "tracking":
                    continue
                name, symbol, price, mc = get_token_metadata(token)
                try:
                    current_mc = float(mc)
                    initial_mc = tracking.get("initial_mc")
                except Exception:
                    continue

                # Stop tracking if MC drops <80%
                if initial_mc and current_mc < 0.8 * initial_mc:
                    token_tracking[token] = {"state": "stopped"}
                    log(f"   ↪ Periodic: Stopped tracking {token} (MC dropped <80%)")

        except Exception as e:
            log(f"⚠️ Exception in periodic MC checker: {e}")
        time.sleep(MC_CHECK_INTERVAL)

# ---------------------------
# Background threads
# ---------------------------
t1 = threading.Thread(target=periodic_mc_checker, daemon=True)
t1.start()

# ---------------------------
# Main app (FastAPI)
# ---------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
