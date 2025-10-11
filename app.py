import os
import time
import asyncio
import requests
import json
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
import logging

# ---------------------------
# Config & environment
# ---------------------------
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_IDS = [c.strip() for c in os.getenv("TELEGRAM_CHAT_IDS", "").split(",") if c.strip()]
MORALIS_API_KEY = os.getenv("MORALIS_API_KEY")
MC_CHECK_INTERVAL = int(os.getenv("MC_CHECK_INTERVAL", "600"))  # seconds
HONEYPOT_SAMPLE_LIMIT = int(os.getenv("HONEYPOT_SAMPLE_LIMIT", "50"))
DEXSCREENER_CACHE_TTL = int(os.getenv("DEXSCREENER_CACHE_TTL", "60"))
HONEYPOT_TTL = 300

if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS and MORALIS_API_KEY):
    raise EnvironmentError("Missing required environment variables.")

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("bnb_monitor")

def log(msg):
    logger.info(msg)

# ---------------------------
# Wallets & aliases
# ---------------------------
WALLETS = {w.lower() for w in [
    "0x749Ee34445f470d8Bdf1A14a79367408B29d579B",
    "0xFDE09A5f5DB264bA7261D25E24EB930d67a87b28",
    "0x65B904285B1c9aB3f6d348446d8c0cEA5b4AeD25",
    "0x9FcA0F07D2F36B76990DA744C86D4991efEa9C20",
    "0xA8fCc482f8e04A0D9C4e11f18Fee714f48EdA4b4",
]}
WALLET_ALIASES = {
    w: alias for w, alias in zip(WALLETS, ["Alaba", "Benjamin", "Caro", "Dolapo", "Ezekiel"])
}

# ---------------------------
# Blacklist
# ---------------------------
BLACKLIST_FILE = "blacklist.json"
def load_blacklist():
    try:
        with open(BLACKLIST_FILE) as f:
            return set([x.lower() for x in json.load(f)])
    except:
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
KNOWN_ROUTER_ADDRESSES = {"0x10ed43c718714eb63d5aa57b78b54704e256024e"}
IGNORED_TOKENS = {t.lower() for t in [
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56",
    "0x55d398326f99059ff775485246999027b3197955",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
]}

# ---------------------------
# Telegram helper
# ---------------------------
def send_telegram_alert(message: str):
    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(url, data={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"})
        except Exception as e:
            log(f"⚠️ Telegram send exception: {e}")

# ---------------------------
# Dexscreener metadata
# ---------------------------
def get_token_metadata(token_address: str):
    token_address = token_address.lower()
    now = time.time()
    if token_address in metadata_cache:
        name, symbol, price, mc, ts = metadata_cache[token_address]
        if now - ts < DEXSCREENER_CACHE_TTL:
            return name, symbol, price, mc
    try:
        r = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{token_address}", timeout=8)
        pairs = r.json().get("pairs", []) if r.status_code == 200 else []
        if pairs:
            p = pairs[0]
            name = p.get("baseToken", {}).get("name", "Unknown")
            symbol = p.get("baseToken", {}).get("symbol", "")
            price = p.get("priceUsd", "N/A")
            mc = p.get("fdv", "N/A")
        else:
            name, symbol, price, mc = "Unknown", "", "N/A", "N/A"
    except:
        name, symbol, price, mc = "Unknown", "", "N/A", "N/A"
    metadata_cache[token_address] = (name, symbol, price, mc, now)
    return name, symbol, price, mc

# ---------------------------
# Honeypot check
# ---------------------------
def is_honeypot(token_address: str):
    token_address = token_address.lower()
    now = time.time()
    if token_address in honeypot_cache:
        res, ts = honeypot_cache[token_address]
        if now - ts < HONEYPOT_TTL:
            return res
    # Simple heuristic: must have sell transactions
    try:
        url = f"https://deep-index.moralis.io/api/v2.2/erc20/{token_address}/transfers?chain=bsc&limit={HONEYPOT_SAMPLE_LIMIT}"
        headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}
        r = requests.get(url, headers=headers, timeout=12)
        transfers = r.json().get("result", []) if r.status_code == 200 else []
        sells_found = any((t.get("to_address") or "").lower() in KNOWN_ROUTER_ADDRESSES for t in transfers)
        is_hp = not sells_found
    except:
        is_hp = True
    honeypot_cache[token_address] = (is_hp, now)
    return is_hp

def is_sell_tx(tx):
    to_addr = (tx.get("to") or tx.get("to_address") or "").lower()
    return to_addr in KNOWN_ROUTER_ADDRESSES

# ---------------------------
# Handle transfer event
# ---------------------------
def handle_transfer_event(tx):
    tx_hash = tx.get("transaction_hash") or tx.get("hash") or ""
    token_address = (tx.get("address") or "").lower()
    from_addr = (tx.get("from_address") or tx.get("from") or "").lower()
    to_addr = (tx.get("to_address") or tx.get("to") or "").lower()
    symbol = tx.get("token_symbol") or tx.get("symbol") or ""

    if not tx_hash or not token_address or tx_hash in seen_transactions:
        return
    seen_transactions.add(tx_hash)
    if token_address in IGNORED_TOKENS or token_address in blacklisted_tokens:
        return

    # SELL
    if from_addr in WALLETS and is_sell_tx(tx):
        alias = WALLET_ALIASES.get(from_addr, from_addr)
        name, symbol_m, price, mc = get_token_metadata(token_address)
        msg = f"⚠️ *Sell Alert*\n{alias} sold token:\n🔹 {name} (`{symbol_m}`)\n💲 {price}\n📊 {mc}\n🪙 `{token_address}`\n[Dexscreener](https://dexscreener.com/bsc/{token_address})"
        send_telegram_alert(msg)
        return

    # BUY
    if to_addr in WALLETS and not is_sell_tx(tx):
        token_to_wallets[token_address].add(to_addr)
        wallet_buy_times[(token_address, to_addr)] = datetime.now().strftime("%Y-%m-%d %H:%M")
        if len(token_to_wallets[token_address]) >= 2:
            tracking = token_tracking.get(token_address, {})
            if tracking.get("state") != "alerted":
                if is_honeypot(token_address):
                    token_tracking[token_address] = {"state": "stopped"}
                    return
                name, symbol_m, price, mc = get_token_metadata(token_address)
                wallets_sorted = sorted(token_to_wallets[token_address], key=lambda w: wallet_buy_times.get((token_address, w), ""))
                wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                msg = f"🚨 *BNB Token Alert!* 🚀\n*{len(wallets_sorted)} wallets bought*\n🔹 {name} (`{symbol_m}`)\n💲 {price}\n📊 {mc}\n📅 {now_str}\n🪙 `{token_address}`\nWallets:\n{wallet_list}\n[Dexscreener](https://dexscreener.com/bsc/{token_address})"
                send_telegram_alert(msg)
                token_tracking[token_address] = {"state": "alerted"}
        if token_address not in token_tracking:
            token_tracking[token_address] = {"state": "tracking"}

# ---------------------------
# FastAPI webhook
# ---------------------------
app = FastAPI(title="BNB Token Monitor")

@app.post("/webhook")
async def webhook(req: Request):
    try:
        data = await req.json()
        txs = data if isinstance(data, list) else [data]
        for tx in txs:
            handle_transfer_event(tx)
        return {"status": "ok"}
    except Exception as e:
        log(f"⚠️ Webhook error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# ---------------------------
# Periodic MC checker
# ---------------------------
async def periodic_mc_checker():
    while True:
        for token, info in list(token_tracking.items()):
            if info.get("state") != "tracking":
                continue
            try:
                name, symbol, price, mc = get_token_metadata(token)
                wallets_sorted = sorted(token_to_wallets[token], key=lambda w: wallet_buy_times.get((token, w), ""))
                wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                msg = f"🚨 *BNB Token Alert!* 🚀\n*{len(wallets_sorted)} wallets bought*\n🔹 {name} (`{symbol}`)\n💲 {price}\n📊 {mc}\n📅 {now_str}\n🪙 `{token}`\nWallets:\n{wallet_list}\n[Dexscreener](https://dexscreener.com/bsc/{token})"
                send_telegram_alert(msg)
                token_tracking[token]["state"] = "alerted"
            except Exception as e:
                log(f"⚠️ Periodic MC check error: {e}")
        await asyncio.sleep(MC_CHECK_INTERVAL)

# ---------------------------
# Startup
# ---------------------------
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(periodic_mc_checker())
    log("✅ BNB Token Monitor started.")
