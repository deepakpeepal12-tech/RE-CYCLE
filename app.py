import os, sqlite3, secrets
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(APP_DIR, "recycle.db"))
MACHINE_TOKEN = os.environ.get("MACHINE_TOKEN", "CHANGE_ME_MACHINE_TOKEN")
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_LONG_RANDOM_SECRET")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
POINTS_PER_BOTTLE = 10

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
                  MAX_CONTENT_LENGTH=1 * 1024 * 1024)

def connect():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          phone TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          expected INTEGER NOT NULL,
          detected INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'waiting',
          points INTEGER NOT NULL DEFAULT 0,
          bin_full INTEGER NOT NULL DEFAULT 0,
          message TEXT DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)

def user_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapped

def machine_required():
    return secrets.compare_digest(request.headers.get("X-Machine-Token", ""), MACHINE_TOKEN)

# Latest IR sensor state (live dashboard)
IR_STATE = {"detected": False, "updated_at": None}

@app.post("/api/machine/ir-status")
def machine_ir_status():
    if not machine_required():
        return jsonify(error="Unauthorized"), 401
    data = request.get_json(silent=True) or {}
    detected = data.get("detected")
    if not isinstance(detected, bool):
        return jsonify(error="detected must be true or false"), 400
    IR_STATE["detected"] = detected
    IR_STATE["updated_at"] = datetime.now().isoformat(timespec="seconds")
    return jsonify(ok=True, detected=detected, updated_at=IR_STATE["updated_at"])

@app.get("/api/user/ir-status")
@user_required
def user_ir_status():
    return jsonify(detected=IR_STATE["detected"], updated_at=IR_STATE["updated_at"])

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

@app.get("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        if not phone.isdigit() or len(phone) != 10:
            flash("Enter a valid 10-digit mobile number.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            try:
                with connect() as con:
                    con.execute("INSERT INTO users(phone,password_hash,created_at) VALUES(?,?,?)",
                                (phone, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("This mobile number is already registered.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        with connect() as con:
            user = con.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["phone"] = user["phone"]
            return redirect(url_for("dashboard"))
        flash("Incorrect mobile number or password.")
    return render_template("login.html")

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/dashboard")
@user_required
def dashboard():
    return render_template("user_dashboard.html", phone=session.get("phone"))

@app.post("/api/user/sessions")
@user_required
def create_user_session():
    data = request.get_json(silent=True) or {}
    try:
        expected = int(data.get("expected", 0))
    except (TypeError, ValueError):
        expected = 0
    if not 1 <= expected <= 50:
        return jsonify(error="Bottle count must be between 1 and 50."), 400
    now = datetime.now().isoformat(timespec="seconds")
    uid = session["user_id"]
    with connect() as con:
        active = con.execute("SELECT id FROM sessions WHERE status IN ('waiting','counting')").fetchone()
        if active:
            return jsonify(error="Machine is busy. Please wait for the current session to finish."), 409
        cur = con.execute("""INSERT INTO sessions(user_id,expected,status,created_at,updated_at)
            VALUES(?,?,'waiting',?,?)""", (uid, expected, now, now))
        sid = cur.lastrowid
    return jsonify(session_id=sid, expected=expected, status="waiting")

@app.get("/api/user/summary")
@user_required
def user_summary():
    uid = session["user_id"]
    with connect() as con:
        stats = con.execute("""SELECT COALESCE(SUM(CASE WHEN status='verified' THEN detected ELSE 0 END),0) bottles,
          COALESCE(SUM(CASE WHEN status='verified' THEN points ELSE 0 END),0) points
          FROM sessions WHERE user_id=?""", (uid,)).fetchone()
        latest = con.execute("""SELECT id,expected,detected,status,points,message,created_at
          FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1""", (uid,)).fetchone()
        history = con.execute("""SELECT expected,detected,status,points,created_at
          FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 10""", (uid,)).fetchall()
    return jsonify(bottles=stats["bottles"], points=stats["points"],
                   latest=dict(latest) if latest else None, history=[dict(x) for x in history])

@app.get("/api/machine/next")
def machine_next():
    if not machine_required():
        return jsonify(error="Unauthorized"), 401
    with connect() as con:
        row = con.execute("""SELECT s.*,u.phone FROM sessions s JOIN users u ON u.id=s.user_id
          WHERE s.status='waiting' ORDER BY s.id LIMIT 1""").fetchone()
        if not row:
            return jsonify(has_session=False)
        now = datetime.now().isoformat(timespec="seconds")
        con.execute("UPDATE sessions SET status='counting',message='Machine started counting',updated_at=? WHERE id=?",
                    (now, row["id"]))
        return jsonify(has_session=True, session_id=row["id"], expected=row["expected"])

@app.post("/api/machine/update")
def machine_update():
    if not machine_required():
        return jsonify(error="Unauthorized"), 401
    data = request.get_json(silent=True) or {}
    try:
        sid, detected = int(data.get("session_id")), int(data.get("detected"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid session or count"), 400
    detected = max(0, min(detected, 1000))
    bin_full = 1 if data.get("bin_full") else 0
    event = data.get("event", "counting")
    now = datetime.now().isoformat(timespec="seconds")
    with connect() as con:
        row = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row:
            return jsonify(error="Session not found"), 404
        if row["status"] not in ("waiting", "counting"):
            return jsonify(status=row["status"], detected=row["detected"], points=row["points"])
        if event == "finish":
            if detected == row["expected"]:
                status, points = "verified", detected * POINTS_PER_BOTTLE
                message = "Bottle count verified. Points awarded."
            else:
                status, points = "mismatch", 0
                message = f"Count mismatch: expected {row['expected']}, detected {detected}. No points awarded."
        else:
            status, points, message = "counting", 0, "Counting bottles..."
        con.execute("""UPDATE sessions SET detected=?,status=?,points=?,bin_full=?,message=?,updated_at=?
          WHERE id=?""", (detected, status, points, bin_full, message, now, sid))
    return jsonify(session_id=sid, detected=detected, status=status, points=points, message=message)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if ADMIN_PASSWORD_HASH and username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Admin login failed. Check deployment environment variables.")
    return render_template("admin_login.html")

@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.get("/admin")
@admin_required
def admin_dashboard():
    with connect() as con:
        totals = con.execute("""SELECT COUNT(*) users FROM users""").fetchone()
        stats = con.execute("""SELECT COALESCE(SUM(CASE WHEN status='verified' THEN detected ELSE 0 END),0) bottles,
          COALESCE(SUM(CASE WHEN status='verified' THEN points ELSE 0 END),0) points,
          SUM(CASE WHEN status IN ('waiting','counting') THEN 1 ELSE 0 END) active
          FROM sessions""").fetchone()
        rows = con.execute("""SELECT s.id,u.phone,s.expected,s.detected,s.status,s.points,s.created_at
          FROM sessions s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 100""").fetchall()
    return render_template("admin_dashboard.html", users=totals["users"], bottles=stats["bottles"],
                           points=stats["points"], active=stats["active"] or 0, rows=rows)

@app.get("/health")
def health():
    return jsonify(ok=True)

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
