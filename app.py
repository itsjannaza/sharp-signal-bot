import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "zain_sharp_bot_prod_secret_2026")

# ==========================================
# SECURITY & LICENSE KEYS CONFIGURATION
# ==========================================
ADMIN_ACCESS_KEY = os.environ.get("ADMIN_ACCESS_KEY", "ZAIN-ADMIN-2026")
DEFAULT_KEYS = {
    "SHARP-PRO-2026",
    "ZAIN-VIP-786",
    "TWZ-MASTER-999",
    ADMIN_ACCESS_KEY,
}
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "ZAIN_WEBHOOK_KEY_2026")

# ==========================================
# TELEGRAM & ADMIN CONFIGURATION
# ==========================================
ADMIN_TELEGRAM_URL = "https://t.me/Zainchartmaster"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "@TWZCommunity")
TELEGRAM_ENABLED = os.environ.get("TELEGRAM_ENABLED", "true").lower() == "true"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "sharp_bot.db")
DB_LOCK = threading.Lock()

AUTO_SCAN_ENABLED = False
AUTO_SCAN_INTERVAL = 60  # seconds
AUTO_SCAN_LOCK = threading.Lock()
LAST_AUTO_SCAN_TS = 0.0


def init_db() -> None:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    pair TEXT NOT NULL,
                    tv_symbol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    timeframe TEXT NOT NULL,
                    entry_delay INTEGER NOT NULL,
                    entry_price REAL,
                    reason TEXT NOT NULL,
                    result TEXT NOT NULL DEFAULT 'PENDING',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_keys (
                    key_code TEXT PRIMARY KEY,
                    role TEXT NOT NULL DEFAULT 'PRO USER',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_used TEXT
                )
                """
            )
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            for k in DEFAULT_KEYS:
                role = "ADMIN" if k == ADMIN_ACCESS_KEY else "PRO USER"
                conn.execute(
                    "INSERT OR IGNORE INTO license_keys (key_code, role, active, created_at) VALUES (?, ?, 1, ?)",
                    (k, role, now_str),
                )
            conn.commit()
        finally:
            conn.close()


def is_valid_license_key(key_code: str) -> tuple[bool, str]:
    clean = (key_code or "").strip()
    if not clean:
        return False, "PRO USER"
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                "SELECT role, active FROM license_keys WHERE key_code = ?",
                (clean,),
            )
            row = cur.fetchone()
            if not row:
                return False, "PRO USER"
            role, active = row[0], int(row[1])
            if active != 1:
                return False, role
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            conn.execute("UPDATE license_keys SET last_used = ? WHERE key_code = ?", (now_str, clean))
            conn.commit()
            return True, role
        finally:
            conn.close()


def list_license_keys() -> list:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                "SELECT key_code, role, active, created_at, last_used FROM license_keys ORDER BY created_at DESC"
            )
            return [
                {
                    "key": r[0],
                    "role": r[1],
                    "active": bool(r[2]),
                    "created_at": r[3],
                    "last_used": r[4] or "Never",
                }
                for r in cur.fetchall()
            ]
        finally:
            conn.close()


def create_license_key(custom_key: str = "", role: str = "PRO USER") -> str:
    clean = (custom_key or "").strip().upper()
    if not clean:
        clean = f"ZAIN-{secrets.token_hex(3).upper()}"
    role_clean = "ADMIN" if str(role).upper() == "ADMIN" else "PRO USER"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO license_keys (key_code, role, active, created_at) VALUES (?, ?, 1, ?)",
                (clean, role_clean, now_str),
            )
            conn.commit()
            return clean
        finally:
            conn.close()


def toggle_license_key(key_code: str, active: bool) -> bool:
    if key_code == ADMIN_ACCESS_KEY and not active:
        return False
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                "UPDATE license_keys SET active = ? WHERE key_code = ?",
                (1 if active else 0, key_code),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def row_to_signal(row: tuple) -> dict:
    return {
        "id": row[0],
        "category": row[1],
        "pair": row[2],
        "tv_symbol": row[3],
        "direction": row[4],
        "confidence": row[5],
        "timeframe": row[6],
        "entry_delay": row[7],
        "entry_price": row[8],
        "reason": row[9],
        "result": row[10],
        "updated_at": row[11],
    }


def get_history_from_db(limit: int = 50) -> list:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                "SELECT id, category, pair, tv_symbol, direction, confidence, timeframe, entry_delay, entry_price, reason, result, created_at FROM signals ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return [row_to_signal(r) for r in cur.fetchall()]
        finally:
            conn.close()


def get_signal_by_id(signal_id: int) -> dict | None:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                "SELECT id, category, pair, tv_symbol, direction, confidence, timeframe, entry_delay, entry_price, reason, result, created_at FROM signals WHERE id = ?",
                (signal_id,),
            )
            row = cur.fetchone()
            return row_to_signal(row) if row else None
        finally:
            conn.close()


def insert_signal_db(sig: dict) -> int:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                """
                INSERT INTO signals (category, pair, tv_symbol, direction, confidence, timeframe, entry_delay, entry_price, reason, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sig["category"],
                    sig["pair"],
                    sig["tv_symbol"],
                    sig["direction"],
                    sig["confidence"],
                    sig["timeframe"],
                    sig["entry_delay"],
                    sig["entry_price"],
                    sig["reason"],
                    sig["result"],
                    sig["updated_at"],
                ),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()


def update_result_db(signal_id: int, result: str) -> bool:
    with DB_LOCK:
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute("UPDATE signals SET result = ? WHERE id = ?", (result, signal_id))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please activate license."}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "Unauthorized."}), 401
        if session.get("role") != "ADMIN":
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated


def send_telegram_signal(sig: dict) -> dict:
    if not TELEGRAM_ENABLED:
        return {"sent": False, "detail": "Telegram disabled"}
    if not TELEGRAM_BOT_TOKEN:
        return {"sent": False, "detail": "Bot token not configured"}

    is_buy = "BUY" in sig["direction"]
    emoji = "🟢" if is_buy else "🔴"
    arrow = "⬆️ CALL (BUY)" if is_buy else "⬇️ PUT (SELL)"
    price_line = f"💵 *Entry Ref:* `{sig['entry_price']}`\n" if sig.get("entry_price") is not None else ""

    text = (
        f"⚡ *SHARP SIGNAL BOT PRO* ⚡\n\n"
        f"📂 *Market:* `{sig['category']}`\n"
        f"📊 *Asset:* `{sig['pair']}`\n"
        f"⏱ *Timeframe:* `{sig['timeframe']}`\n"
        f"{emoji} *Next Trade:* *{arrow}*\n"
        f"🎯 *Confidence:* `{sig['confidence']}%`\n"
        f"⏳ *Entry Countdown:* `{sig['entry_delay']}s`\n"
        f"{price_line}"
        f"🧠 *Analysis:* {sig['reason']}\n\n"
        f"👤 Admin: {ADMIN_TELEGRAM_URL}"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"sent": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"sent": False, "detail": e.read().decode("utf-8", errors="ignore")}
    except Exception as e:
        return {"sent": False, "detail": str(e)}


def compute_ema(values: list, period: int) -> list:
    if not values:
        return []
    k = 2.0 / (period + 1.0)
    ema = [values[0]]
    for price in values[1:]:
        ema.append(price * k + ema[-1] * (1.0 - k))
    return ema


def compute_rsi(closes: list, period: int = 14) -> float:
    if len(closes) <= period:
        return 50.0
    gains = []
    losses = []
    for i in range(1, len(closes)):
        diff = closes[i] - closes[i - 1]
        gains.append(max(diff, 0.0))
        losses.append(max(-diff, 0.0))
    avg_gain = sum(gains[-period:]) / period
    avg_loss = sum(losses[-period:]) / period
    if avg_loss == 0:
        return 75.0 if avg_gain > 0 else 50.0
    rs = avg_gain / avg_loss
    return round(100.0 - (100.0 / (1.0 + rs)), 1)


def map_yahoo_symbol(pair: str, tv_symbol: str) -> str:
    clean = pair.replace(" OTC", "").strip().upper()
    if "/" in clean:
        base, quote = clean.split("/", 1)
        crypto_bases = {"BTC", "ETH", "LTC", "XRP", "BCH", "EOS", "ADA", "DOT", "LINK", "UNI", "SOL", "AVAX", "DOGE", "SHIB", "BNB"}
        if quote == "USD" and base in crypto_bases:
            return f"{base}-USD"
        return f"{base}{quote}=X"

    stock_map = {
        "AAPL (APPLE)": "AAPL", "MSFT (MICROSOFT)": "MSFT", "AMZN (AMAZON)": "AMZN",
        "GOOGL (GOOGLE)": "GOOGL", "TSLA (TESLA)": "TSLA", "META (META)": "META",
        "NFLX (NETFLIX)": "NFLX", "NVDA (NVIDIA)": "NVDA", "AMD": "AMD",
        "INTC (INTEL)": "INTC", "BA (BOEING)": "BA", "KO (COCA-COLA)": "KO",
        "DIS (DISNEY)": "DIS", "MCD (MCDONALD'S)": "MCD", "NKE (NIKE)": "NKE",
        "V (VISA)": "V", "MA (MASTERCARD)": "MA", "PYPL (PAYPAL)": "PYPL",
        "SHOP (SHOPIFY)": "SHOP", "ZM (ZOOM)": "ZM",
    }
    if clean in stock_map:
        return stock_map[clean]

    other_map = {
        "USOIL": "CL=F", "USOIL OTC": "CL=F", "WTI CRUDE OIL": "CL=F",
        "UKOIL": "BZ=F", "UKOIL OTC": "BZ=F", "BRENT CRUDE OIL": "BZ=F",
        "NATURAL GAS": "NG=F", "US500 (S&P 500)": "^GSPC", "US100 (NASDAQ 100)": "^NDX",
        "US30 (DOW JONES)": "^DJI", "UK100 (FTSE 100)": "^FTSE", "DE40 (DAX 40)": "^GDAXI",
        "FR40 (CAC 40)": "^FCHI", "JP225 (NIKKEI 225)": "^N225", "HK50 (HANG SENG)": "^HSI",
        "AU200 (ASX 200)": "^AXJO", "EU50 (EURO STOXX 50)": "^STOXX50E",
    }
    return other_map.get(clean, tv_symbol.split(":")[-1])


def fetch_real_closes(pair: str, tv_symbol: str, timeframe: str) -> list:
    tf_map = {"1m": ("1m", "1d"), "5m": ("5m", "2d"), "15m": ("15m", "5d"), "60m": ("1h", "10d")}
    interval, rng = tf_map.get(timeframe, ("1m", "1d"))

    clean = pair.replace(" OTC", "").strip().upper()
    if clean.endswith("/USD"):
        base = clean.split("/")[0]
        binance_int = {"1m": "1m", "5m": "5m", "15m": "15m", "60m": "1h"}.get(timeframe, "1m")
        url = f"https://api.binance.com/api/v3/klines?symbol={base}USDT&interval={binance_int}&limit=80"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                rows = json.loads(resp.read().decode("utf-8"))
                closes = [float(r[4]) for r in rows if len(r) > 4]
                if len(closes) >= 25:
                    return closes
        except Exception:
            pass

    y_sym = map_yahoo_symbol(pair, tv_symbol)
    url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(y_sym)}?interval={interval}&range={rng}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            result = (payload.get("chart") or {}).get("result") or []
            if result:
                quote = ((result[0].get("indicators") or {}).get("quote") or [{}])[0]
                closes = [float(c) for c in (quote.get("close") or []) if c is not None]
                if len(closes) >= 25:
                    return closes
    except Exception:
        pass

    return []


def evaluate_live_market_signal(pair: str, tv_symbol: str, timeframe: str) -> dict:
    closes = fetch_real_closes(pair, tv_symbol, timeframe)
    if len(closes) >= 25:
        ema9 = compute_ema(closes, 9)
        ema21 = compute_ema(closes, 21)
        rsi = compute_rsi(closes, 14)

        last_close = closes[-1]
        prev_close = closes[-2]
        prev_2 = closes[-3]
        trend_diff = ema9[-1] - ema21[-1]
        candle_push = last_close - prev_close
        two_bar_momentum = last_close - prev_2

        buy_pts = 0
        sell_pts = 0
        reasons = []

        if trend_diff > 0:
            buy_pts += 2
            reasons.append("EMA9 > EMA21")
        else:
            sell_pts += 2
            reasons.append("EMA9 < EMA21")

        if candle_push > 0 and two_bar_momentum > 0:
            buy_pts += 2
            reasons.append("Bullish Impulse")
        elif candle_push < 0 and two_bar_momentum < 0:
            sell_pts += 2
            reasons.append("Bearish Impulse")
        elif candle_push > 0:
            buy_pts += 1
            reasons.append("Green Close")
        else:
            sell_pts += 1
            reasons.append("Red Close")

        if rsi <= 32:
            buy_pts += 2
            reasons.append(f"RSI Oversold ({rsi})")
        elif rsi >= 68:
            sell_pts += 2
            reasons.append(f"RSI Overbought ({rsi})")
        elif 45 <= rsi <= 55:
            reasons.append(f"RSI Neutral ({rsi})")
        elif rsi > 55:
            buy_pts += 1
            reasons.append(f"RSI {rsi}")
        else:
            sell_pts += 1
            reasons.append(f"RSI {rsi}")

        is_buy = buy_pts >= sell_pts
        spread = abs(buy_pts - sell_pts)
        confidence = min(95, max(72, 74 + spread * 4))
        direction = "BUY (CALL)" if is_buy else "SELL (PUT)"

        return {
            "direction": direction,
            "confidence": confidence,
            "entry_price": round(last_close, 6),
            "reason": " | ".join(reasons) + " [Live Feed]",
        }

    seed_val = sum(ord(ch) for ch in f"{pair}:{timeframe}:{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}")
    is_buy = (seed_val % 2) == 0
    return {
        "direction": "BUY (CALL)" if is_buy else "SELL (PUT)",
        "confidence": 65,
        "entry_price": None,
        "reason": "No Live Feed (OTC / Off-Hours) — Low Confidence Reference",
    }


def calculate_signal_score(payload: dict) -> dict:
    raw_side = str(payload.get("side", payload.get("action", ""))).strip().upper()
    if not raw_side:
        return evaluate_live_market_signal(
            str(payload.get("pair", "EUR/USD")),
            str(payload.get("tv_symbol", payload.get("symbol", "FX:EURUSD"))),
            str(payload.get("timeframe", "1m")),
        )

    is_buy = "BUY" in raw_side or "CALL" in raw_side or "LONG" in raw_side
    score = 74
    reasons = ["Webhook Alert"]

    ema_trend = payload.get("ema_trend")
    if ema_trend is not None:
        try:
            ema_val = float(ema_trend)
            if (is_buy and ema_val > 0) or (not is_buy and ema_val < 0):
                score += 10
                reasons.append("EMA Aligned")
        except ValueError:
            pass

    rsi = payload.get("rsi")
    if rsi is not None:
        try:
            rsi_val = float(rsi)
            if (is_buy and rsi_val <= 38) or (not is_buy and rsi_val >= 62):
                score += 9
                reasons.append(f"RSI {rsi_val}")
        except ValueError:
            pass

    if payload.get("confidence") is not None:
        try:
            score = int(round((score + float(payload["confidence"])) / 2))
        except ValueError:
            pass

    entry_price = None
    if payload.get("price") is not None:
        try:
            entry_price = float(payload["price"])
        except ValueError:
            entry_price = None

    confidence = max(70, min(96, int(score)))
    direction = "BUY (CALL)" if is_buy else "SELL (PUT)"
    return {
        "direction": direction,
        "confidence": confidence,
        "entry_price": entry_price,
        "reason": " | ".join(reasons),
    }


def schedule_auto_result_check(signal_id: int, sig: dict) -> None:
    if sig.get("entry_price") is None:
        return

    tf_seconds = {"1m": 60, "5m": 300, "15m": 900, "60m": 3600}.get(sig.get("timeframe", "1m"), 60)
    wait_time = max(15, int(sig.get("entry_delay", 10)) + tf_seconds)

    def _worker():
        time.sleep(wait_time)
        current = get_signal_by_id(signal_id)
        if not current or current.get("result") != "PENDING":
            return
        closes = fetch_real_closes(current["pair"], current["tv_symbol"], current["timeframe"])
        if not closes:
            return
        exit_price = closes[-1]
        entry_price = float(current["entry_price"])
        is_buy = "BUY" in current["direction"]
        if exit_price == entry_price:
            return
        won = (exit_price > entry_price) if is_buy else (exit_price < entry_price)
        update_result_db(signal_id, "WIN" if won else "LOSS")

    threading.Thread(target=_worker, daemon=True).start()


def process_incoming_signal(data: dict) -> tuple:
    evaluated = calculate_signal_score(data)
    category = str(data.get("category", "FOREX LIVE")).upper()
    pair = str(data.get("pair", "EUR/USD"))
    tv_symbol = str(data.get("tv_symbol", data.get("symbol", "FX:EURUSD")))
    timeframe = str(data.get("timeframe", "1m"))
    entry_delay = int(data.get("entry_delay", 10))

    new_sig = {
        "category": category,
        "pair": pair,
        "tv_symbol": tv_symbol,
        "direction": evaluated["direction"],
        "confidence": evaluated["confidence"],
        "timeframe": timeframe,
        "entry_delay": entry_delay,
        "entry_price": evaluated.get("entry_price"),
        "reason": evaluated["reason"],
        "result": "PENDING",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    sig_id = insert_signal_db(new_sig)
    new_sig["id"] = sig_id

    schedule_auto_result_check(sig_id, new_sig)
    tg_status = send_telegram_signal(new_sig)
    return new_sig, tg_status


WATCHLIST_SCAN = [
    {"category": "FOREX LIVE", "pair": "EUR/USD", "tv_symbol": "FX:EURUSD"},
    {"category": "FOREX LIVE", "pair": "GBP/USD", "tv_symbol": "FX:GBPUSD"},
    {"category": "FOREX LIVE", "pair": "USD/JPY", "tv_symbol": "FX:USDJPY"},
    {"category": "CRYPTO", "pair": "BTC/USD", "tv_symbol": "BINANCE:BTCUSDT"},
    {"category": "CRYPTO", "pair": "ETH/USD", "tv_symbol": "BINANCE:ETHUSDT"},
]


def _auto_scanner_loop() -> None:
    global LAST_AUTO_SCAN_TS
    idx = 0
    while True:
        time.sleep(5)
        if not AUTO_SCAN_ENABLED:
            continue
        now = time.time()
        if now - LAST_AUTO_SCAN_TS < AUTO_SCAN_INTERVAL:
            continue
        with AUTO_SCAN_LOCK:
            if not AUTO_SCAN_ENABLED or (time.time() - LAST_AUTO_SCAN_TS < AUTO_SCAN_INTERVAL):
                continue
            LAST_AUTO_SCAN_TS = time.time()
            target = WATCHLIST_SCAN[idx % len(WATCHLIST_SCAN)]
            idx += 1
            try:
                process_incoming_signal({
                    "category": target["category"],
                    "pair": target["pair"],
                    "tv_symbol": target["tv_symbol"],
                    "timeframe": "1m",
                    "entry_delay": 10,
                })
            except Exception:
                pass


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        key = request.form.get("license_key", "").strip()
        valid, role = is_valid_license_key(key)
        if valid:
            session["authenticated"] = True
            session["license_key"] = key
            session["role"] = role
            return redirect(url_for("index"))
        error = "Invalid or deactivated License Key! Please contact Admin on Telegram."
    return render_template("login.html", error=error, admin_url=ADMIN_TELEGRAM_URL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        admin_url=ADMIN_TELEGRAM_URL,
        user_role=session.get("role", "PRO USER"),
        webhook_secret=WEBHOOK_SECRET,
    )


@app.route("/api/state", methods=["GET"])
@login_required
def get_state():
    history = get_history_from_db(limit=50)
    latest = history[0] if history else {
        "id": 0,
        "category": "FOREX LIVE",
        "pair": "EUR/USD",
        "tv_symbol": "FX:EURUSD",
        "direction": "READY",
        "confidence": 0,
        "timeframe": "1m",
        "entry_delay": 0,
        "entry_price": None,
        "reason": "Ready for live market scan.",
        "result": "PENDING",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    wins = sum(1 for s in history if s.get("result") == "WIN")
    losses = sum(1 for s in history if s.get("result") == "LOSS")
    decided = wins + losses
    win_rate = round((wins / decided) * 100, 1) if decided > 0 else 0.0

    return jsonify({
        "latest": latest,
        "history": history,
        "stats": {
            "total": len(history),
            "wins": wins,
            "losses": losses,
            "win_rate": win_rate,
        },
        "auto_scan": AUTO_SCAN_ENABLED,
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN) and TELEGRAM_ENABLED,
    })


@app.route("/api/auto-scan", methods=["POST"])
@login_required
def toggle_auto_scan():
    global AUTO_SCAN_ENABLED, LAST_AUTO_SCAN_TS
    body = request.get_json(silent=True) or {}
    if "enabled" in body:
        AUTO_SCAN_ENABLED = bool(body["enabled"])
    else:
        AUTO_SCAN_ENABLED = not AUTO_SCAN_ENABLED
    if AUTO_SCAN_ENABLED:
        LAST_AUTO_SCAN_TS = 0.0
    return jsonify({"status": "ok", "auto_scan": AUTO_SCAN_ENABLED}), 200


@app.route("/api/admin/keys", methods=["GET", "POST"])
@admin_required
def manage_keys():
    if request.method == "GET":
        return jsonify({"keys": list_license_keys()}), 200
    body = request.get_json(silent=True) or {}
    created = create_license_key(
        custom_key=str(body.get("key", "")),
        role=str(body.get("role", "PRO USER")),
    )
    return jsonify({"status": "ok", "created_key": created, "keys": list_license_keys()}), 200


@app.route("/api/admin/keys/toggle", methods=["POST"])
@admin_required
def set_key_status():
    body = request.get_json(silent=True) or {}
    key_code = str(body.get("key", "")).strip()
    active = bool(body.get("active", True))
    if not toggle_license_key(key_code, active):
        return jsonify({"error": "Cannot modify key"}), 400
    return jsonify({"status": "ok", "keys": list_license_keys()}), 200


@app.route("/webhook", methods=["POST"])
def tradingview_webhook():
    data = request.get_json(silent=True)
    if not data:
        raw_text = (request.data or b"").decode("utf-8", errors="ignore").strip()
        data = {
            "side": "SELL" if "SELL" in raw_text.upper() or "PUT" in raw_text.upper() else "BUY",
            "raw": raw_text,
        }

    provided_secret = request.args.get("secret") or request.headers.get("X-Webhook-Secret") or data.get("secret")
    if WEBHOOK_SECRET and provided_secret != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized webhook secret"}), 403

    new_sig, tg_status = process_incoming_signal(data)
    return jsonify({"status": "ok", "signal": new_sig, "telegram": tg_status}), 200


@app.route("/api/generate-signal", methods=["POST"])
@login_required
def generate_signal_api():
    body = request.get_json(silent=True) or {}
    new_sig, tg_status = process_incoming_signal(body)
    return jsonify({"status": "ok", "signal": new_sig, "telegram": tg_status}), 200


@app.route("/api/signal/<int:signal_id>/result", methods=["POST"])
@login_required
def mark_signal_result(signal_id: int):
    body = request.get_json(silent=True) or {}
    result = str(body.get("result", "")).upper()
    if result not in ("WIN", "LOSS", "PENDING"):
        return jsonify({"error": "Invalid result"}), 400

    if not update_result_db(signal_id, result):
        return jsonify({"error": "Signal not found"}), 404

    updated = get_signal_by_id(signal_id)
    return jsonify({"status": "ok", "signal": updated}), 200


init_db()
threading.Thread(target=_auto_scanner_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)