import os
import time
import requests
import json
import threading
import re
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime

# === Load environment variables ===
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_IDS")
MORALIS_API_KEY = os.getenv("MORALIS_API_KEY")

if TELEGRAM_CHAT_IDS:
    TELEGRAM_CHAT_IDS = [chat_id.strip() for chat_id in TELEGRAM_CHAT_IDS.split(",")]

required_vars = {
    "TELEGRAM_BOT_TOKEN": TELEGRAM_BOT_TOKEN,
    "TELEGRAM_CHAT_IDS": TELEGRAM_CHAT_IDS,
    "MORALIS_API_KEY": MORALIS_API_KEY,
}
missing = [key for key, value in required_vars.items() if not value]
if missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")

# === Blacklist system ===
BLACKLIST_FILE = "blacklist_bnb.json"

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(list(blacklist), f)

blacklisted_tokens = load_blacklist()

# === Wallets to track ===
WALLETS = [
    "0x749Ee34445f470d8Bdf1A14a79367408B29d579B",
    "0xFDE09A5f5DB264bA7261D25E24EB930d67a87b28",
    "0x65B904285B1c9aB3f6d348446d8c0cEA5b4AeD25",
    "0x9FcA0F07D2F36B76990DA744C86D4991efEa9C20",
    "0xA8fCc482f8e04A0D9C4e11f18Fee714f48EdA4b4",
]

WALLET_ALIASES = {
    "0x749Ee34445f470d8Bdf1A14a79367408B29d579B": "Alaba",
    "0xFDE09A5f5DB264bA7261D25E24EB930d67a87b28": "Benjamin",
    "0x65B904285B1c9aB3f6d348446d8c0cEA5b4AeD25": "Caro",
    "0x9FcA0F07D2F36B76990DA744C86D4991efEa9C20": "Dolapo",
    "0xA8fCc482f8e04A0D9C4e11f18Fee714f48EdA4b4": "Ezekiel"
}

# === Global state ===
seen_transactions = set()
token_to_wallets = defaultdict(set)
wallet_buy_times = {}
initial_market_caps = {}
metadata_cache = {}
CACHE_TTL = 30

# === Ignored tokens ===
IGNORED_TOKENS = {
    "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",  # WBNB
    "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",  # BUSD
    "0x55d398326f99059fF775485246999027B3197955",  # USDT
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"   # USDC
}

# === Helper functions ===
def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

# === Fetch Transactions via Moralis API ===
def fetch_transactions(wallet):
    url = f"https://deep-index.moralis.io/api/v2.2/{wallet}/erc20/transfers?chain=bsc"
    headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code != 200:
            log(f"⚠️ Moralis fetch error ({res.status_code}): {res.text}")
            return []

        data = res.json()
        if not isinstance(data, dict) or "result" not in data:
            log(f"⚠️ Unexpected response format from Moralis for {wallet}")
            return []

        parsed_txs = []
        for tx in data["result"]:
            to_addr = tx.get("to_address", "").lower()
            from_addr = tx.get("from_address", "").lower()
            contract = tx.get("address", "").lower()
            tx_hash = tx.get("transaction_hash")
            symbol = tx.get("token_symbol", "")
            
            # Only include incoming transfers to this wallet
            if to_addr == wallet.lower() and contract not in IGNORED_TOKENS:
                parsed_txs.append({
                    "hash": tx_hash,
                    "tokenSymbol": symbol,
                    "contractAddress": contract
                })

        return parsed_txs

    except Exception as e:
        log(f"⚠️ Moralis API error: {e}")
        return []

# === Token metadata (Dexscreener) ===
def get_token_metadata(token_address):
    now = time.time()
    if token_address in metadata_cache:
        name, symbol, price, market_cap, timestamp = metadata_cache[token_address]
        if now - timestamp < CACHE_TTL:
            return name, symbol, price, market_cap

    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    try:
        res = requests.get(url)
        data = res.json().get("pairs", [])
        if data:
            pair = data[0]
            name = pair.get("baseToken", {}).get("name", "Unknown")
            symbol = pair.get("baseToken", {}).get("symbol", "")
            price = round(float(pair.get("priceUsd", 0)), 8)
            market_cap = pair.get("fdv", "N/A")
        else:
            name, symbol, price, market_cap = "Unknown", "", "N/A", "N/A"
    except Exception as e:
        log(f"⚠️ Dexscreener error: {e}")
        name, symbol, price, market_cap = "Unknown", "", "N/A", "N/A"

    metadata_cache[token_address] = (name, symbol, price, market_cap, now)
    return name, symbol, price, market_cap

# === Telegram alert ===
def send_telegram_alert(message):
    for chat_id in TELEGRAM_CHAT_IDS:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": False
            }
        )

# === Telegram blacklist commands ===
def listen_for_blacklist_commands():
    log("📨 Listening for Telegram blacklist commands...")
    offset = None
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"timeout": 30}
            if offset:
                params["offset"] = offset
            res = requests.get(url, params=params)
            updates = res.json().get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = msg.get("text", "").strip()
                chat_id = str(msg.get("chat", {}).get("id", ""))

                if chat_id not in TELEGRAM_CHAT_IDS:
                    continue

                if re.fullmatch(r"0x[a-fA-F0-9]{40}", text):
                    if text in blacklisted_tokens:
                        send_telegram_alert(f"⚠️ Token already blacklisted:\n`{text}`")
                    else:
                        blacklisted_tokens.add(text)
                        save_blacklist(blacklisted_tokens)
                        send_telegram_alert(f"✅ Token blacklisted:\n`{text}`")
        except Exception as e:
            log(f"⚠️ Telegram listener error: {e}")
        time.sleep(3)

# === Main logic ===
def main():
    log("🔁 Starting BNB wallet monitoring (Moralis API)...")
    while True:
        for wallet in WALLETS:
            log(f"🔍 Checking wallet: {wallet}")
            txs = fetch_transactions(wallet)
            for tx in txs:
                sig = tx.get("hash")
                token_address = tx.get("contractAddress")
                if not token_address or sig in seen_transactions:
                    continue
                seen_transactions.add(sig)

                if token_address in IGNORED_TOKENS or token_address in blacklisted_tokens:
                    continue

                token_to_wallets[token_address].add(wallet)
                key = (token_address, wallet)
                if key not in wallet_buy_times:
                    wallet_buy_times[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Trigger alert when 2+ watched wallets have same token
                if len(token_to_wallets[token_address]) >= 2:
                    name, symbol, price, market_cap = get_token_metadata(token_address)
                    dex_url = f"https://dexscreener.com/bsc/{token_address}"
                    twitter_url = f"https://twitter.com/search?q={token_address}&src=typed_query"

                    try:
                        current_mc = float(market_cap)
                    except:
                        current_mc = None

                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                    return_text = ""
                    if current_mc is not None:
                        if token_address not in initial_market_caps:
                            initial_market_caps[token_address] = (current_mc, now_str)
                        else:
                            initial_mc, first_time = initial_market_caps[token_address]
                            pct_return = ((current_mc - initial_mc) / initial_mc) * 100
                            if pct_return > 0:
                                return_text = f"\n🟩 *Return Since First Alert:* +*{pct_return:.2f}%*"
                            elif pct_return < 0:
                                return_text = f"\n🟥 *Return Since First Alert:* -*{abs(pct_return):.2f}%*"
                            else:
                                return_text = f"\n🟨 *Return Since First Alert:* *0.00%*"

                    wallets_sorted = sorted(
                        token_to_wallets[token_address],
                        key=lambda w: wallet_buy_times.get((token_address, w), "")
                    )
                    wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                    msg = (
                        f"🚨 *BNB Token Alert!*\n"
                        f"*{len(token_to_wallets[token_address])} watched wallets* have bought this token:\n\n"
                        f"🔹 Token: *{name}* (`{symbol}`)\n"
                        f"💲 Price: `${price}`\n"
                        f"📊 Market Cap: `${market_cap}`{return_text}\n"
                        f"🪙 Address: `{token_address}`\n\n"
                        f"👛 Wallets:\n{wallet_list}\n\n"
                        f"[🔎 View on Dexscreener]({dex_url}) | [🐦 Search on Twitter]({twitter_url})"
                    )
                    send_telegram_alert(msg)

            time.sleep(2)  # Gentle delay between wallets to save API credits
        time.sleep(15)

if __name__ == "__main__":
    threading.Thread(target=listen_for_blacklist_commands, daemon=True).start()
    main()
