import os
import time
import requests
import json
import threading
import re
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime, timedelta
import logging

# ---------------------------
# Configuration & env load
# ---------------------------
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
logger = logging.getLogger("bnb_monitor")

def log(msg):
    logger.info(msg)

# ---------------------------
# Blacklist system
# ---------------------------
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

# ---------------------------
# Wallets & aliases
# ---------------------------
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

# ---------------------------
# Globals and caches
# ---------------------------
seen_transactions = set()
token_to_wallets = defaultdict(set)
wallet_buy_times = {}
initial_market_caps = {}  # token -> (initial_mc_float, first_time_str)
metadata_cache = {}       # token -> (name, symbol, price, market_cap, timestamp)
CACHE_TTL = 60  # seconds for metadata cache
honeypot_cache = {}       # token -> (is_honeypot_bool, checked_at)
HONEYPOT_TTL = 300        # seconds to cache honeypot result

# token_tracking: state info for alerts and lifecycle
token_tracking = {}  # token -> {'state': 'tracking'|'stopped'|'alerted', 'initial_mc':float, 'first_time':str}

# Known router addresses for heuristics (PancakeSwap v2 router)
KNOWN_ROUTER_ADDRESSES = {
    "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(),  # PancakeSwap Router v2 (mainnet)
    # add others if needed
}

# Ignored tokens (stablecoins / wrappers)
IGNORED_TOKENS = {
    "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c".lower(),  # WBNB
    "0xe9e7cea3dedca5984780bafc599bd69add087d56".lower(),  # BUSD
    "0x55d398326f99059ff775485246999027b3197955".lower(),  # USDT
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d".lower()   # USDC
}

# ---------------------------
# Helpers: Telegram
# ---------------------------
def send_telegram_alert(message):
    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": False
            }
            r = requests.post(url, data=data, timeout=10)
            if r.status_code != 200:
                log(f"⚠️ Telegram send failed ({r.status_code}): {r.text}")
        except Exception as e:
            log(f"⚠️ Telegram send exception: {e}")

# ---------------------------
# Moralis: fetch recent ERC20 (BEP20) transfers for a wallet
# - optimized: limit results, only recent, sequential polling
# ---------------------------
def fetch_transactions(wallet, limit=20):
    """
    Fetch recent token transfers for `wallet` using Moralis v2.2 endpoint.
    Only returns transfers that are incoming OR outgoing (we'll use both).
    """
    url = f"https://deep-index.moralis.io/api/v2.2/{wallet}/erc20/transfers?chain=bsc&limit={limit}"
    headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code != 200:
            log(f"⚠️ Moralis fetch error ({res.status_code}): {res.text[:200]}")
            return []

        data = res.json()
        # Moralis returns dict with "result" list. Validate.
        if not isinstance(data, dict) or "result" not in data or not isinstance(data["result"], list):
            log(f"⚠️ Unexpected Moralis response format for {wallet}: {str(data)[:200]}")
            return []

        parsed = []
        for tx in data["result"]:
            # Moralis field names (per expected response)
            tx_hash = tx.get("transaction_hash")
            token_addr = tx.get("address", "").lower()
            from_addr = tx.get("from_address", "").lower()
            to_addr = tx.get("to_address", "").lower()
            symbol = tx.get("token_symbol", "") or tx.get("symbol", "")
            # Only consider transfers with contract address
            if not token_addr:
                continue
            parsed.append({
                "hash": tx_hash,
                "contractAddress": token_addr,
                "from": from_addr,
                "to": to_addr,
                "symbol": symbol
            })
        return parsed

    except Exception as e:
        log(f"⚠️ Moralis API error for wallet {wallet}: {e}")
        return []

# ---------------------------
# Dexscreener metadata (cached)
# ---------------------------
def get_token_metadata(token_address):
    now = time.time()
    token_address = token_address.lower()
    if token_address in metadata_cache:
        name, symbol, price, market_cap, ts = metadata_cache[token_address]
        if now - ts < CACHE_TTL:
            return name, symbol, price, market_cap

    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            log(f"⚠️ Dexscreener fetch failed ({r.status_code}): {r.text[:200]}")
            name, symbol, price, market_cap = "Unknown", "", "N/A", "N/A"
        else:
            data = r.json().get("pairs", [])
            if data:
                pair = data[0]
                name = pair.get("baseToken", {}).get("name", "Unknown")
                symbol = pair.get("baseToken", {}).get("symbol", "")
                price = pair.get("priceUsd", "N/A")
                # fdv may be string or number
                market_cap = pair.get("fdv", "N/A")
            else:
                name, symbol, price, market_cap = "Unknown", "", "N/A", "N/A"
    except Exception as e:
        log(f"⚠️ Dexscreener error: {e}")
        name, symbol, price, market_cap = "Unknown", "", "N/A", "N/A"

    metadata_cache[token_address] = (name, symbol, price, market_cap, now)
    return name, symbol, price, market_cap

# ---------------------------
# Honeypot detection (heuristic)
# - Checks if token has tradable pair
# - Checks recent transfers for evidence of sells to pair/router
# - Cached to avoid repeated Moralis calls
# ---------------------------
def is_honeypot(token_address, sample_limit=50):
    token_address = token_address.lower()
    now = time.time()
    # return cached result if fresh
    if token_address in honeypot_cache:
        result, checked_at = honeypot_cache[token_address]
        if now - checked_at < HONEYPOT_TTL:
            return result

    log(f"🔎 Running honeypot heuristic for {token_address} ...")

    # 1) Check Dexscreener for a pair / liquidity info
    try:
        r = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{token_address}", timeout=8)
        pairs = r.json().get("pairs", []) if r.status_code == 200 else []
    except Exception as e:
        log(f"⚠️ Dexscreener error in honeypot check: {e}")
        pairs = []

    if not pairs:
        # no pair => suspicious (potential honeypot)
        honeypot_cache[token_address] = (True, now)
        log(f"⚠️ Honeypot heuristic: no dex pair found for {token_address}")
        return True

    # try to extract pair address(s) if available in feed (not guaranteed)
    pair_addresses = set()
    for pair in pairs:
        pair_addr = pair.get("pairAddress") or pair.get("pair", {}).get("address")
        if pair_addr:
            pair_addresses.add(pair_addr.lower())

    # 2) Look at recent token transfers (search for sells)
    #    If there are outgoing transfers to router/pair addresses, it's likely sellable (not honeypot)
    #    If we see NO sells in recent N transfers, mark suspicious
    sells_found = False
    try:
        # Moralis token transfers (by contract) - fetch recent transfers
        url = f"https://deep-index.moralis.io/api/v2.2/erc20/{token_address}/transfers?chain=bsc&limit={sample_limit}"
        headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}
        res = requests.get(url, headers=headers, timeout=12)
        if res.status_code == 200:
            data = res.json()
            transfers = data.get("result", []) if isinstance(data, dict) else []
            for t in transfers:
                to_addr = (t.get("to_address") or "").lower()
                from_addr = (t.get("from_address") or "").lower()
                # consider a "sell" when to_addr is a known router or pair
                if to_addr in KNOWN_ROUTER_ADDRESSES or to_addr in pair_addresses:
                    sells_found = True
                    break
        else:
            log(f"⚠️ Moralis token transfers fetch failed in honeypot check ({res.status_code})")
    except Exception as e:
        log(f"⚠️ Moralis honeypot check error: {e}")

    # If no sells found, mark honeypot True
    is_hp = not sells_found
    honeypot_cache[token_address] = (is_hp, now)
    if is_hp:
        log(f"⚠️ Honeypot heuristic flagged {token_address} as possible honeypot (no sells found in recent transfers).")
    else:
        log(f"✅ Honeypot heuristic suggests {token_address} is sellable (sells found).")
    return is_hp

# ---------------------------
# Utility: stop tracking token
# ---------------------------
def stop_tracking_token(token_address, reason=""):
    token_address = token_address.lower()
    if token_address in token_to_wallets:
        del token_to_wallets[token_address]
    # mark state stopped
    token_tracking[token_address] = {'state': 'stopped'}
    log(f"⛔ Stopped tracking {token_address}. Reason: {reason}")

# ---------------------------
# Helper: check for sell tx
# - Heuristic: if tx.from == wallet and tx.to is router or pair -> treat as sell
# ---------------------------
def is_sell_tx(tx):
    to_addr = (tx.get("to") or "").lower()
    # if to a known router, treat as sell
    if to_addr in KNOWN_ROUTER_ADDRESSES:
        return True
    # if to a known pair (we don't have full list) - best-effort handled elsewhere
    return False

# ---------------------------
# Main loop
# ---------------------------
def main():
    log("🔁 Starting BNB wallet monitoring (Moralis-enhanced)...")
    # gentle pacing to limit Moralis usage: we will poll each wallet sequentially with short delay
    while True:
        for wallet in WALLETS:
            log(f"🔍 Checking wallet: {wallet}")
            txs = fetch_transactions(wallet, limit=20)
            log(f"   ↪ Got {len(txs)} transfers for {wallet}")

            for tx in txs:
                tx_hash = tx.get("hash")
                token_address = (tx.get("contractAddress") or "").lower()
                from_addr = (tx.get("from") or "").lower()
                to_addr = (tx.get("to") or "").lower()

                if not tx_hash or not token_address:
                    continue

                # skip already seen txs
                if tx_hash in seen_transactions:
                    continue
                seen_transactions.add(tx_hash)

                # if token is ignored or blacklisted, skip
                if token_address in IGNORED_TOKENS or token_address in blacklisted_tokens:
                    log(f"   ↪ Ignored/blacklisted token {token_address}")
                    continue

                # If this transaction is an outgoing sell by a watched wallet -> send sell alert
                if from_addr == wallet.lower() and is_sell_tx(tx):
                    # send sell alert
                    alias = WALLET_ALIASES.get(wallet, wallet)
                    name, symbol, price, market_cap = get_token_metadata(token_address)
                    msg = (
                        f"⚠️ *Sell Alert*\n"
                        f"{alias} sold token:\n\n"
                        f"🔹 Token: *{name}* (`{symbol}`)\n"
                        f"💲 Price: `${price}`\n"
                        f"📊 Market Cap: `${market_cap}`\n"
                        f"🪙 Address: `{token_address}`\n"
                        f"🔁 Tx: `{tx_hash}`\n"
                    )
                    send_telegram_alert(msg)
                    log(f"   ↪ Sent sell alert for {token_address} by {alias}")

                # If incoming transfer to watched wallet -> treat as buy
                if to_addr == wallet.lower():
                    token_to_wallets[token_address].add(wallet)
                    key = (token_address, wallet)
                    if key not in wallet_buy_times:
                        wallet_buy_times[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log(f"   ↪ {WALLET_ALIASES.get(wallet, wallet)} received token {token_address} (tx {tx_hash})")

                    # When 2+ watched wallets bought same token -> begin tracking if not already
                    if len(token_to_wallets[token_address]) >= 2:
                        # If we have already stopped tracking this token, skip
                        tk_state = token_tracking.get(token_address, {}).get('state')
                        if tk_state == 'stopped':
                            log(f"   ↪ Token {token_address} previously stopped; skipping.")
                            continue

                        # If token not yet tracked, set initial market cap
                        if token_address not in token_tracking or token_tracking[token_address].get('state') is None:
                            name, symbol, price, market_cap = get_token_metadata(token_address)
                            try:
                                initial_mc = float(market_cap)
                            except Exception:
                                initial_mc = None

                            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                            if initial_mc is not None:
                                token_tracking[token_address] = {
                                    'state': 'tracking',
                                    'initial_mc': initial_mc,
                                    'first_time': now_str
                                }
                                initial_market_caps[token_address] = (initial_mc, now_str)
                                log(f"   ↪ Started tracking {token_address} with initial MC {initial_mc} at {now_str}")
                            else:
                                # If we can't determine market cap, still set tracking but with None
                                token_tracking[token_address] = {
                                    'state': 'tracking',
                                    'initial_mc': None,
                                    'first_time': now_str
                                }
                                log(f"   ↪ Started tracking {token_address} but initial MC unknown.")

                        # If token is under tracking, evaluate conditions
                        tracking = token_tracking.get(token_address, {})
                        if tracking.get('state') == 'tracking':
                            name, symbol, price, market_cap = get_token_metadata(token_address)
                            # check honeypot first
                            try:
                                hp = is_honeypot(token_address)
                            except Exception as e:
                                log(f"   ↪ Honeypot check error for {token_address}: {e}")
                                hp = True  # be conservative if error

                            if hp:
                                log(f"   ↪ {token_address} flagged as honeypot — will NOT alert and will stop tracking.")
                                # stop tracking and do not alert
                                stop_tracking_token(token_address, reason="honeypot detected")
                                continue

                            # parse market cap
                            try:
                                current_mc = float(market_cap)
                            except Exception:
                                current_mc = None

                            # If initial_mc missing, set it now if possible
                            if tracking.get('initial_mc') is None and current_mc is not None:
                                token_tracking[token_address]['initial_mc'] = current_mc
                                token_tracking[token_address]['first_time'] = datetime.now().strftime("%Y-%m-%d %H:%M")
                                log(f"   ↪ Set initial MC for {token_address} to {current_mc}")

                            initial_mc = token_tracking[token_address].get('initial_mc')

                            # If we have initial_mc and current_mc, check thresholds
                            if initial_mc and current_mc:
                                # If market cap dropped below 80% -> stop tracking completely
                                if current_mc < 0.8 * initial_mc:
                                    stop_tracking_token(token_address, reason=f"Market cap dropped below 80% ({current_mc} < 0.8*{initial_mc})")
                                    continue

                                # If market cap increased by +200% (i.e., >= 3x initial) and we haven't alerted yet
                                if current_mc >= 3.0 * initial_mc and token_tracking[token_address].get('state') == 'tracking':
                                    # send alert if not honeypot (we already checked)
                                    wallets_sorted = sorted(
                                        token_to_wallets[token_address],
                                        key=lambda w: wallet_buy_times.get((token_address, w), "")
                                    )
                                    wallet_list = "\n".join([f"• {WALLET_ALIASES.get(w, w)}" for w in wallets_sorted])
                                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                                    # calculate return %
                                    pct_return = ((current_mc - initial_mc) / initial_mc) * 100
                                    msg = (
                                        f"🚨 *BNB Token BIG MOVE!* 🚀\n"
                                        f"*{len(token_to_wallets[token_address])} watched wallets* bought this token and market cap is up +200%:\n\n"
                                        f"🔹 Token: *{name}* (`{symbol}`)\n"
                                        f"💲 Price: `${price}`\n"
                                        f"📊 Market Cap: `${market_cap}`\n"
                                        f"🟩 *Return Since First Alert:* +{pct_return:.2f}%\n"
                                        f"📅 First Alert: {token_tracking[token_address].get('first_time')}\n"
                                        f"📅 Now: {now_str}\n"
                                        f"🪙 Address: `{token_address}`\n\n"
                                        f"👛 Wallets (by time bought):\n{wallet_list}\n\n"
                                        f"[🔎 View on Dexscreener](https://dexscreener.com/bsc/{token_address}) | [🐦 Search on Twitter](https://twitter.com/search?q={token_address})"
                                    )
                                    send_telegram_alert(msg)
                                    log(f"   ↪ Sent +200% alert for {token_address}")
                                    # mark as alerted so we don't spam
                                    token_tracking[token_address]['state'] = 'alerted'
                            else:
                                log(f"   ↪ Unable to evaluate MC thresholds for {token_address} (initial_mc:{initial_mc}, current_mc:{current_mc})")
                # end incoming buy handling
            # end for each tx

            # Gentle delay between wallets to avoid hammering Moralis (and conserve units)
            time.sleep(2)

        # End wallet loop; sleep a bit before next full pass
        time.sleep(15)

# ---------------------------
# Telegram blacklist listener (unchanged, background thread)
# ---------------------------
def listen_for_blacklist_commands():
    log("📨 Listening for Telegram blacklist commands...")
    offset = None
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"timeout": 30}
            if offset:
                params["offset"] = offset
            res = requests.get(url, params=params, timeout=30)
            updates = res.json().get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = msg.get("text", "").strip()
                chat_id = str(msg.get("chat", {}).get("id", ""))

                if chat_id not in TELEGRAM_CHAT_IDS:
                    continue

                if re.fullmatch(r"0x[a-fA-F0-9]{40}", text):
                    if text.lower() in blacklisted_tokens:
                        send_telegram_alert(f"⚠️ Token already blacklisted:\n`{text}`")
                    else:
                        blacklisted_tokens.add(text.lower())
                        save_blacklist(blacklisted_tokens)
                        send_telegram_alert(f"✅ Token blacklisted:\n`{text}`")
        except Exception as e:
            log(f"⚠️ Telegram listener error: {e}")
        time.sleep(3)

# ---------------------------
# Entrypoint
# ---------------------------
if __name__ == "__main__":
    # start listener thread
    threading.Thread(target=listen_for_blacklist_commands, daemon=True).start()
    main()
