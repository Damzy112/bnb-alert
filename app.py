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

MC_CHECK_INTERVAL = int(os.getenv("MC_CHECK_INTERVAL", "600"))  # 10 min default
HONEYPOT_SAMPLE_LIMIT = int(os.getenv("HONEYPOT_SAMPLE_LIMIT", "50"))
DEXSCREENER_CACHE_TTL = int(os.getenv("DEXSCREENER_CACHE_TTL", "60"))
TELEGRAM_POLL_INTERVAL = int(os.getenv("TELEGRAM_POLL_INTERVAL", "3"))

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
# Blacklist system
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
# Globals
# ---------------------------
seen_transactions = set()
token_to_wallets = defaultdict(set)
wallet_buy_times = {}
token_tracking = {}
metadata_cache = {}
honeypot_cache = {}
dex_cache = {}

# Router heuristics
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
# Utility: Dexscreener metadata
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
# Honeypot check
# ---------------------------
HONEYPOT_TTL = 600
def is_honeypot(token_address: str, sample_limit: int = HONEYPOT_SAMPLE_LIMIT):
    token_address = token_address.lower()
    now = time.time()
    if token_address in honeypot_cache:
        res, checked_at = honeypot_cache[token_address]
        if now - checked_at < HONEYPOT_TTL:
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

    # Moralis transfers to detect sells
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
    except Exception as e:
        log(f"⚠️ Moralis honeypot fetch exception: {e}")

    is_hp = not sells_found
    honeypot_cache[token_address] = (is_hp, now)
    log(f"⚠️ Honeypot heuristic: {token_address} flagged: {is_hp}")
    return is_hp

# ---------------------------
# Sell tx heuristic
# ---------------------------
def is_sell_tx_from_payload(tx_dict: dict):
    to_addr = (tx_dict.get("to") or tx_dict.get("to_address") or tx_dict.get("toAddress") or "").lower()
    if not to_addr:
        return False
    return to_addr in KNOWN_ROUTER_ADDRESSES

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

        log(f"📥 Processing tx {tx_hash}: token {token_address}, from {from_addr}, to {to_addr}")

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

        # SELL detection
        if from_addr in WALLETS and is_sell_tx_from_payload(tx):
            alias = WALLET_ALIASES.get(from_addr, from_addr)
            log(f"   ↪ Detected SELL by {alias} for token {token_address}")
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

        # BUY detection
        if to_addr in WALLETS:
            watcher = to_addr
            token_to_wallets[token_address].add(watcher)
            key = (token_address, watcher)
            if key not in wallet_buy_times:
                wallet_buy_times[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log(f"   ↪ Detected BUY by {WALLET_ALIASES.get(watcher, watcher)} for token {token_address}")

            if len(token_to_wallets[token_address]) >= 2:
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

                # Honeypot check
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

                    # Log current MC evaluation
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
                        log(f"   ↪ Tracking token {token_address}, initial MC: {initial_mc}, current MC: {current_mc}")
                        if current_mc < 0.8 * initial_mc:
                            token_tracking[token_address] = {"state": "stopped"}
                            log(f"   ↪ Stopped tracking {token_address} because MC dropped below 80% ({current_mc} < 0.8*{initial_mc})")
                            return
    except Exception as e:
        log(f"⚠️ Exception in handle_transfer_event: {e}")

# ---------------------------
# Periodic MC checker
# ---------------------------
async def periodic_mc_checker():
    while True:
        try:
            tracked = [tk for tk, info in token_tracking.items() if info.get("state") == "tracking"]
            if tracked:
                log(f"🔁 Periodic MC checker: {len(tracked)} tokens tracked")
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
                        log(f"   ↪ Periodic MC evaluation: token {token}, initial MC {initial}, current MC {current_mc}")
                        if current_mc < 0.8 * initial:
                            token_tracking[token] = {"state": "stopped"}
                            log(f"   ↪ Stopped tracking {token} due to MC drop below 80%")
                except Exception as e:
                    log(f"⚠️ Error during periodic MC check for {token}: {e}")
            await asyncio.sleep(MC_CHECK_INTERVAL)
        except Exception as e:
            log(f"⚠️ periodic_mc_checker crashed: {e}")
            await asyncio.sleep(30)

# ---------------------------
# Telegram blacklist listener
# ---------------------------
def telegram_blacklist_listener():
    log("📨 Telegram blacklist listener started")
    offset = None
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?timeout=30"
            if offset:
                url += f"&offset={offset}"
            r = requests.get(url, timeout=15)
            data = r.json()
            for update in data.get("result", []):
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = (msg.get("text") or "").strip()
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if chat_id not in TELEGRAM_CHAT_IDS:
                    log(f"   ↪ Ignoring message from unauthorized chat {chat_id}")
                    continue
                if re.fullmatch(r"0x[a-fA-F0-9]{40}", text):
                    addr = text.lower()
                    if addr in blacklisted_tokens:
                        log(f"   ↪ Token {addr} already blacklisted")
                        send_telegram_alert(f"⚠️ Token already blacklisted:\n`{text}`")
                    else:
                        blacklisted_tokens.add(addr)
                        save_blacklist(blacklisted_tokens)
                        log(f"   ↪ Token {addr} added to blacklist via Telegram")
                        send_telegram_alert(f"✅ Token blacklisted:\n`{text}`")
        except Exception as e:
            log(f"⚠️ Telegram listener error: {e}")
        time.sleep(TELEGRAM_POLL_INTERVAL)

# ---------------------------
# FastAPI webhook endpoint
# ---------------------------
@app.post("/webhook")
async def webhook(req: Request):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    txs = data.get("event") or data.get("events") or data.get("payload")
    if not txs:
        log("⚠️ Received webhook with no events")
        return {"status": "ignored"}
    if not isinstance(txs, list):
        txs = [txs]
    for tx in txs:
        handle_transfer_event(tx)
    return {"status": "ok"}

# ---------------------------
# Main entry
# ---------------------------
if __name__ == "__main__":
    # Start background tasks
    threading.Thread(target=telegram_blacklist_listener, daemon=True).start()
    asyncio.run(periodic_mc_checker())
