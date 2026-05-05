import os, re, uuid, json, sqlite3, logging, csv, io, hashlib, secrets, string
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse, RedirectResponse
import uvicorn, httpx

# ── Config ──────────────────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "leadgen.db"
MS_TENANT_ID = os.getenv("MS_TENANT_ID", "")
MS_CLIENT_ID = os.getenv("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET", "")
MAIL_FROM = os.getenv("MAIL_FROM", "cedric@itdaily.be")
CC_EMAILS = ["femke@itdaily.be", "press@itdaily.be"]
SESSION_COOKIE = "leadgen_session"
SESSION_DURATION = timedelta(hours=24)
BASE_URL = os.getenv("BASE_URL", "https://leads.itdaily.com")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("leadgen")

app = FastAPI(title="ITdaily Lead Generation", docs_url=None, redoc_url=None)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ── Rate limiting ───────────────────────────────────────────────────────
rate_limits: dict = {}
RATE_LIMIT = 10
RATE_WINDOW = 3600

login_rate_limits: dict = {}
LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW = 900

def check_rate_limit(ip: str, limits: dict = None, max_count: int = None, window: int = None) -> bool:
    if limits is None:
        limits = rate_limits
    if max_count is None:
        max_count = RATE_LIMIT
    if window is None:
        window = RATE_WINDOW
    now = datetime.now().timestamp()
    if ip in limits:
        count, window_start = limits[ip]
        if now - window_start > window:
            limits[ip] = (1, now)
            return True
        if count >= max_count:
            return False
        limits[ip] = (count + 1, window_start)
    else:
        limits[ip] = (1, now)
    return True

# ── CSRF ────────────────────────────────────────────────────────────────
csrf_tokens: dict = {}

@app.get("/api/csrf-token")
async def get_csrf_token():
    token = uuid.uuid4().hex
    csrf_tokens[token] = datetime.now().timestamp() + 3600
    now = datetime.now().timestamp()
    for k in [k for k, v in csrf_tokens.items() if v < now]:
        del csrf_tokens[k]
    return {"token": token}

def verify_csrf(token: str) -> bool:
    if token in csrf_tokens and csrf_tokens[token] > datetime.now().timestamp():
        del csrf_tokens[token]
        return True
    csrf_tokens.pop(token, None)
    return False

# ── Password hashing ───────────────────────────────────────────────────
def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'),
        bytes.fromhex(salt), 100_000
    ).hex()
    return pw_hash, salt

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    computed, _ = hash_password(password, stored_salt)
    return secrets.compare_digest(computed, stored_hash)

# ── Session management ─────────────────────────────────────────────────
def create_session(user_id: int, ip: str = "", ua: str = "") -> str:
    session_id = secrets.token_hex(32)
    now = datetime.now()
    expires = now + SESSION_DURATION
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (id, user_id, created_at, expires_at, ip_address, user_agent) VALUES (?,?,?,?,?,?)",
        (session_id, user_id, now.isoformat(), expires.isoformat(), ip, ua)
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
    conn.commit()
    conn.close()
    return session_id

def get_session_user(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    conn = get_db()
    row = conn.execute(
        """SELECT s.id as session_id, s.user_id, u.username, u.display_name, u.is_admin
           FROM sessions s JOIN users u ON s.user_id = u.id
           WHERE s.id=? AND s.expires_at > ?""",
        (session_id, datetime.now().isoformat())
    ).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)

def require_auth(request: Request) -> dict:
    user = get_session_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return user

def require_admin(request: Request) -> dict:
    user = require_auth(request)
    if not user["is_admin"]:
        raise HTTPException(403, "Admin access required")
    return user

# ── Database ────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'submitted',
        created_at TEXT NOT NULL,
        company_name TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        logo_path TEXT,
        company_website TEXT,
        whitepaper_title TEXT,
        whitepaper_paths TEXT,
        campaign_name TEXT NOT NULL,
        number_of_leads INTEGER NOT NULL,
        start_date TEXT NOT NULL,
        end_date TEXT NOT NULL,
        exclusion_list_path TEXT,
        country TEXT NOT NULL,
        lead_distribution TEXT,
        industry TEXT,
        number_of_employees TEXT,
        job_level TEXT,
        max_leads_per_company INTEGER,
        company_annual_revenue TEXT,
        notes TEXT,
        multiple_choice_answer TEXT,
        ip_address TEXT,
        user_agent TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        display_name TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS form_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        client_name TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        submitted_at TEXT,
        submission_id INTEGER,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (submission_id) REFERENCES submissions(id)
    );
    """)

    # Migration: add form_link_id to submissions if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(submissions)").fetchall()]
    if "form_link_id" not in cols:
        conn.execute("ALTER TABLE submissions ADD COLUMN form_link_id INTEGER")

    # Seed default admin if no users exist
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        pw_hash, salt = hash_password("test12345")
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, display_name, is_admin, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            ("cedric", pw_hash, salt, "Cedric", 1, now, now)
        )
        logger.info("Default admin user 'cedric' created")

    conn.commit()
    conn.close()

init_db()

# ── Slug generation ─────────────────────────────────────────────────────
def generate_form_slug(client_name: str) -> str:
    base = client_name.lower().strip()
    base = re.sub(r'[^a-z0-9\s-]', '', base)
    base = re.sub(r'[\s]+', '-', base)
    base = re.sub(r'-+', '-', base).strip('-')[:50]
    if not base:
        base = "form"
    chars = string.ascii_lowercase + string.digits
    suffix = ''.join(secrets.choice(chars) for _ in range(6))
    slug = f"{base}-{suffix}"
    conn = get_db()
    while conn.execute("SELECT id FROM form_links WHERE slug=?", (slug,)).fetchone():
        suffix = ''.join(secrets.choice(chars) for _ in range(6))
        slug = f"{base}-{suffix}"
    conn.close()
    return slug

def generate_submission_slug(company_name: str) -> str:
    slug = company_name.lower().strip()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'[\s]+', '-', slug)
    slug = re.sub(r'-+', '-', slug).strip('-')[:60]
    if not slug:
        slug = "submission"
    conn = get_db()
    base_slug = slug
    counter = 1
    while conn.execute("SELECT id FROM submissions WHERE slug=?", (slug,)).fetchone():
        counter += 1
        slug = f"{base_slug}-{counter}"
    conn.close()
    return slug

# ── File upload ─────────────────────────────────────────────────────────
ALLOWED_IMAGE = {'.jpg', '.jpeg', '.png'}
ALLOWED_PDF = {'.pdf'}
ALLOWED_SHEET = {'.csv', '.xls', '.xlsx'}
MAX_IMG = 5 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024

async def save_upload(file, allowed: set, max_size: int, subfolder: str) -> str:
    if not file or not hasattr(file, 'filename') or not file.filename:
        return ""
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(400, f"File type {ext} not allowed. Allowed: {', '.join(allowed)}")
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(400, f"File too large. Max: {max_size // (1024*1024)}MB")
    safe_name = f"{uuid.uuid4().hex}{ext}"
    save_dir = UPLOAD_DIR / subfolder
    save_dir.mkdir(parents=True, exist_ok=True)
    (save_dir / safe_name).write_bytes(content)
    return f"/uploads/{subfolder}/{safe_name}"

# ── Email ───────────────────────────────────────────────────────────────
def build_email_html(data: dict) -> str:
    rows = ""
    field_labels = {
        "company_name": "Company Name", "contact_email": "Contact Email",
        "company_website": "Company Website", "whitepaper_title": "Whitepaper Title",
        "campaign_name": "Lead Campaign Name", "number_of_leads": "Number of Leads",
        "start_date": "Start Date", "end_date": "End Date",
        "country": "Country", "lead_distribution": "Lead Distribution by Country/Region",
        "industry": "Industry", "number_of_employees": "Number of Employees",
        "job_level": "Job Level", "max_leads_per_company": "Max Leads per Company",
        "company_annual_revenue": "Company Annual Revenue",
        "notes": "Notes", "multiple_choice_answer": "Multiple-choice contacts"
    }
    for key, label in field_labels.items():
        val = data.get(key, "")
        if isinstance(val, list):
            val = ", ".join(val) if val else "\u2014"
        if not val:
            val = "\u2014"
        rows += f'<tr><td style="padding:10px 16px;border-bottom:1px solid #222;color:#999;font-weight:700;width:40%;vertical-align:top">{label}</td><td style="padding:10px 16px;border-bottom:1px solid #222;color:#fff">{val}</td></tr>'

    return f"""<!DOCTYPE html><html><body style="margin:0;padding:0;background:#000;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif">
<div style="max-width:640px;margin:0 auto;padding:32px 24px">
<div style="text-align:center;padding-bottom:24px;border-bottom:1px solid #222;margin-bottom:32px">
<span style="font-size:24px;font-weight:400"><span style="color:#fff">IT</span><span style="color:#00D2D2">daily.</span></span>
</div>
<h2 style="color:#fff;font-size:20px;margin-bottom:8px">Lead Campaign Submission</h2>
<p style="color:#999;font-size:14px;margin-bottom:32px">Submitted on {datetime.now().strftime('%d.%m.%Y at %H:%M')}</p>
<table style="width:100%;border-collapse:collapse;background:#111;border-radius:8px;overflow:hidden">{rows}</table>
<div style="margin-top:40px;padding-top:24px;border-top:1px solid #222;text-align:center;color:#666;font-size:12px">
<p>&copy; {datetime.now().year} ITdaily. All rights reserved.</p>
</div></div></body></html>"""

def get_graph_token():
    """Get OAuth2 access token via client credentials flow."""
    url = f"https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": MS_CLIENT_ID,
        "client_secret": MS_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = httpx.post(url, data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]

def send_email(to_email: str, cc_emails: list, subject: str, html_body: str):
    if not MS_TENANT_ID or not MS_CLIENT_ID or not MS_CLIENT_SECRET:
        logger.warning("Microsoft Graph not configured, skipping email")
        return False
    try:
        token = get_graph_token()
        to_recipients = [{"emailAddress": {"address": to_email}}]
        cc_recipients = [{"emailAddress": {"address": e}} for e in (cc_emails or [])]
        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html_body},
                "from": {"emailAddress": {"address": MAIL_FROM}},
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients,
            },
            "saveToSentItems": "true",
        }
        url = f"https://graph.microsoft.com/v1.0/users/{MAIL_FROM}/sendMail"
        resp = httpx.post(url, json=payload, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, timeout=15)
        resp.raise_for_status()
        logger.info(f"Email sent to {to_email}, CC: {cc_emails}")
        return True
    except Exception as e:
        logger.error(f"Email failed: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
async def login(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip, login_rate_limits, LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW):
        raise HTTPException(429, "Too many login attempts. Please try again in 15 minutes.")

    body = await request.json()
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    if not username or not password:
        raise HTTPException(400, "Username and password are required")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user["password_hash"], user["password_salt"]):
        raise HTTPException(401, "Invalid username or password")

    ua = request.headers.get("user-agent", "")
    session_id = create_session(user["id"], ip, ua)

    response = JSONResponse({
        "success": True,
        "user": {"id": user["id"], "username": user["username"], "display_name": user["display_name"], "is_admin": bool(user["is_admin"])}
    })
    response.set_cookie(
        SESSION_COOKIE, session_id,
        httponly=True, samesite="lax", secure=True,
        max_age=int(SESSION_DURATION.total_seconds()),
        path="/"
    )
    return response

@app.post("/api/auth/logout")
async def logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        conn.commit()
        conn.close()
    response = JSONResponse({"success": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response

@app.get("/api/auth/me")
async def auth_me(request: Request):
    user = get_session_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return {"id": user["user_id"], "username": user["username"], "display_name": user["display_name"], "is_admin": bool(user["is_admin"])}

# ═══════════════════════════════════════════════════════════════════════
# FORM LINK ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/forms/create")
async def create_form_link(request: Request):
    user = require_auth(request)
    body = await request.json()
    client_name = body.get("client_name", "").strip()
    if not client_name or len(client_name) < 2:
        raise HTTPException(400, "Client name is required (min 2 characters)")
    if len(client_name) > 100:
        raise HTTPException(400, "Client name too long (max 100 characters)")

    slug = generate_form_slug(client_name)
    now = datetime.now().isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO form_links (slug, client_name, status, created_at, created_by) VALUES (?,?,?,?,?)",
        (slug, client_name, "pending", now, user["user_id"])
    )
    conn.commit()
    conn.close()

    url = f"{BASE_URL}/{slug}"
    logger.info(f"Form link created: {url} for client '{client_name}' by user '{user['username']}'")
    return {"success": True, "slug": slug, "url": url, "client_name": client_name}

@app.get("/api/forms/pending")
async def list_pending_forms(request: Request):
    require_auth(request)
    conn = get_db()
    rows = conn.execute(
        """SELECT fl.id, fl.slug, fl.client_name, fl.created_at, u.display_name as created_by_name
           FROM form_links fl JOIN users u ON fl.created_by = u.id
           WHERE fl.status='pending' ORDER BY fl.created_at DESC"""
    ).fetchall()
    conn.close()
    return [{"id": r["id"], "slug": r["slug"], "client_name": r["client_name"],
             "created_at": r["created_at"], "created_by": r["created_by_name"],
             "url": f"{BASE_URL}/{r['slug']}"} for r in rows]

@app.get("/api/forms/submitted")
async def list_submitted_forms(request: Request):
    require_auth(request)
    date_from = request.query_params.get("from", "")
    date_to = request.query_params.get("to", "")

    query = """SELECT fl.id, fl.slug, fl.client_name, fl.created_at, fl.submitted_at,
                      s.company_name, s.contact_email, s.campaign_name,
                      u.display_name as created_by_name
               FROM form_links fl
               JOIN users u ON fl.created_by = u.id
               LEFT JOIN submissions s ON fl.submission_id = s.id
               WHERE fl.status='submitted'"""
    params = []

    if date_from:
        query += " AND fl.submitted_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND fl.submitted_at <= ?"
        params.append(date_to + "T23:59:59")

    query += " ORDER BY fl.submitted_at DESC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [{"id": r["id"], "slug": r["slug"], "client_name": r["client_name"],
             "created_at": r["created_at"], "submitted_at": r["submitted_at"],
             "company_name": r["company_name"], "contact_email": r["contact_email"],
             "campaign_name": r["campaign_name"], "created_by": r["created_by_name"]} for r in rows]

@app.get("/api/forms/check/{slug}")
async def check_form_link(slug: str):
    conn = get_db()
    row = conn.execute("SELECT id, slug, client_name, status FROM form_links WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if not row or row["status"] != "pending":
        raise HTTPException(404, "Form not found or no longer available")
    return {"valid": True, "client_name": row["client_name"]}

@app.get("/api/forms/{form_id}")
async def get_form_detail(form_id: int, request: Request):
    require_auth(request)
    conn = get_db()
    fl = conn.execute(
        """SELECT fl.*, u.display_name as created_by_name
           FROM form_links fl JOIN users u ON fl.created_by = u.id
           WHERE fl.id=?""", (form_id,)
    ).fetchone()
    if not fl:
        conn.close()
        raise HTTPException(404, "Form link not found")

    result = dict(fl)
    result["url"] = f"{BASE_URL}/{fl['slug']}"

    if fl["submission_id"]:
        sub = conn.execute("SELECT * FROM submissions WHERE id=?", (fl["submission_id"],)).fetchone()
        if sub:
            sub_dict = dict(sub)
            for k in ("industry", "number_of_employees", "job_level", "company_annual_revenue", "whitepaper_paths"):
                try:
                    sub_dict[k] = json.loads(sub_dict[k]) if sub_dict[k] else []
                except:
                    sub_dict[k] = []
            result["submission"] = sub_dict
    conn.close()
    return result

@app.delete("/api/forms/{form_id}")
async def delete_form_link(form_id: int, request: Request):
    user = require_auth(request)
    conn = get_db()
    fl = conn.execute("SELECT * FROM form_links WHERE id=?", (form_id,)).fetchone()
    if not fl:
        conn.close()
        raise HTTPException(404, "Form link not found")
    require_admin(request)
    if fl["status"] != "pending":
        conn.execute("DELETE FROM submissions WHERE form_link_id=?", (form_id,))
    conn.execute("DELETE FROM form_links WHERE id=?", (form_id,))
    conn.commit()
    conn.close()
    return {"success": True}

# ═══════════════════════════════════════════════════════════════════════
# USER MANAGEMENT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/users")
async def list_users(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("SELECT id, username, display_name, is_admin, created_at FROM users ORDER BY created_at").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/users")
async def create_user(request: Request):
    require_admin(request)
    body = await request.json()
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")
    display_name = body.get("display_name", "").strip()
    is_admin = 1 if body.get("is_admin", False) else 0

    if not username or len(username) < 2:
        raise HTTPException(400, "Username required (min 2 characters)")
    if not re.match(r'^[a-z0-9._-]+$', username):
        raise HTTPException(400, "Username may only contain lowercase letters, numbers, dots, dashes and underscores")
    if not password or len(password) < 6:
        raise HTTPException(400, "Password required (min 6 characters)")
    if not display_name:
        display_name = username.title()

    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        conn.close()
        raise HTTPException(409, "Username already exists")

    pw_hash, salt = hash_password(password)
    now = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO users (username, password_hash, password_salt, display_name, is_admin, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (username, pw_hash, salt, display_name, is_admin, now, now)
    )
    conn.commit()
    new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    logger.info(f"User '{username}' created (admin={is_admin})")
    return {"success": True, "id": new_id, "username": username}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, request: Request):
    current = require_admin(request)
    if current["user_id"] == user_id:
        raise HTTPException(400, "Cannot delete your own account")
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "User not found")
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.put("/api/users/{user_id}/password")
async def change_password(user_id: int, request: Request):
    current = require_auth(request)
    body = await request.json()
    new_password = body.get("new_password", "")

    if not new_password or len(new_password) < 6:
        raise HTTPException(400, "New password required (min 6 characters)")

    # Non-admins can only change their own password and must provide current password
    if not current["is_admin"] and current["user_id"] != user_id:
        raise HTTPException(403, "You can only change your own password")

    if not current["is_admin"]:
        current_password = body.get("current_password", "")
        if not current_password:
            raise HTTPException(400, "Current password is required")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        if not user or not verify_password(current_password, user["password_hash"], user["password_salt"]):
            raise HTTPException(401, "Current password is incorrect")

    pw_hash, salt = hash_password(new_password)
    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash=?, password_salt=?, updated_at=? WHERE id=?",
        (pw_hash, salt, datetime.now().isoformat(), user_id)
    )
    # Invalidate all sessions for this user except current
    conn.execute("DELETE FROM sessions WHERE user_id=? AND id!=?", (user_id, current.get("session_id", "")))
    conn.commit()
    conn.close()
    return {"success": True}

@app.put("/api/users/{user_id}/admin")
async def toggle_admin(user_id: int, request: Request):
    current = require_admin(request)
    if current["user_id"] == user_id:
        raise HTTPException(400, "Cannot change your own admin status")
    body = await request.json()
    is_admin = 1 if body.get("is_admin", False) else 0
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "User not found")
    conn.execute("UPDATE users SET is_admin=?, updated_at=? WHERE id=?", (is_admin, datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()
    return {"success": True}

# ═══════════════════════════════════════════════════════════════════════
# EMAIL TEST ENDPOINT
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/test-email")
async def test_email(request: Request):
    require_admin(request)
    html = """<!DOCTYPE html><html><body style="margin:0;padding:0;background:#000;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif">
<div style="max-width:640px;margin:0 auto;padding:32px 24px">
<div style="text-align:center;padding-bottom:24px;border-bottom:1px solid #222;margin-bottom:32px">
<span style="font-size:24px;font-weight:400"><span style="color:#fff">IT</span><span style="color:#00D2D2">daily.</span></span>
</div>
<h2 style="color:#fff;font-size:20px;margin-bottom:8px">SMTP Test Email</h2>
<p style="color:#ccc;font-size:15px;margin-bottom:16px">This is a test email from the ITdaily Lead Generation platform.</p>
<p style="color:#999;font-size:14px">If you received this email, your SMTP configuration is working correctly.</p>
<p style="color:#666;font-size:13px;margin-top:24px">Sent at: """ + datetime.now().strftime('%d.%m.%Y %H:%M:%S') + """</p>
</div></body></html>"""

    success = send_email(
        to_email="cedric@itdaily.be",
        cc_emails=[],
        subject="ITdaily Leads \u2013 SMTP Test",
        html_body=html
    )
    if success:
        return {"success": True, "message": "Test email sent to cedric@itdaily.be"}
    else:
        raise HTTPException(500, "Email sending failed. Check SMTP configuration and server logs.")

# ═══════════════════════════════════════════════════════════════════════
# FILE DOWNLOAD (auth-protected)
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/download")
async def download_file(request: Request, path: str = ""):
    require_auth(request)
    if not path:
        raise HTTPException(400, "Path parameter required")
    # Strip leading /uploads/ if present
    clean = path.lstrip("/")
    if clean.startswith("uploads/"):
        clean = clean[8:]
    file_path = (UPLOAD_DIR / clean).resolve()
    if not str(file_path).startswith(str(UPLOAD_DIR.resolve())):
        raise HTTPException(403, "Access denied")
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(file_path, filename=file_path.name)

# ═══════════════════════════════════════════════════════════════════════
# SUBMIT ENDPOINT (public, with form_link_slug)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/submit")
async def submit_form(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        raise HTTPException(429, "Too many submissions. Please try again later.")

    form = await request.form()
    csrf = form.get("csrf_token", "")
    if not verify_csrf(str(csrf)):
        raise HTTPException(403, "Invalid security token. Please refresh the page.")

    # Check form link slug
    form_link_slug = str(form.get("form_link_slug", "")).strip()
    form_link_id = None
    if form_link_slug:
        conn = get_db()
        fl = conn.execute("SELECT id, status FROM form_links WHERE slug=?", (form_link_slug,)).fetchone()
        conn.close()
        if not fl:
            raise HTTPException(404, "Form link not found")
        if fl["status"] != "pending":
            raise HTTPException(400, "This form has already been submitted")
        form_link_id = fl["id"]

    # ── Validate step 1 ──
    company_name = str(form.get("company_name", "")).strip()
    if not company_name or len(company_name) < 2 or len(company_name) > 100:
        raise HTTPException(400, "Company name: 2\u2013100 characters required.")

    contact_email = str(form.get("contact_email", "")).strip()
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', contact_email):
        raise HTTPException(400, "Invalid email address.")

    company_website = str(form.get("company_website", "")).strip()

    campaign_name = str(form.get("campaign_name", "")).strip()
    if not campaign_name:
        raise HTTPException(400, "Lead campaign name is required.")

    try:
        number_of_leads = int(form.get("number_of_leads", 0))
        if number_of_leads < 1:
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(400, "Number of leads must be at least 1.")

    start_date = str(form.get("start_date", "")).strip()
    end_date = str(form.get("end_date", "")).strip()
    if not start_date or not end_date:
        raise HTTPException(400, "Start and end dates are required.")
    if end_date < start_date:
        raise HTTPException(400, "End date must be on or after start date.")

    # ── Validate step 2 ──
    country = str(form.get("country", "")).strip()
    if not country or len(country) < 2:
        raise HTTPException(400, "Country is required (min 2 characters).")

    # ── File uploads ──
    logo_path = ""
    logo = form.get("logo")
    if logo and hasattr(logo, 'filename') and logo.filename:
        logo_path = await save_upload(logo, ALLOWED_IMAGE, MAX_IMG, "logos")

    whitepaper_paths = []
    i = 0
    while True:
        key = f"whitepapers_{i}"
        wp = form.get(key)
        if not wp:
            break
        if hasattr(wp, 'filename') and wp.filename:
            path = await save_upload(wp, ALLOWED_PDF, MAX_FILE, "whitepapers")
            if path:
                whitepaper_paths.append(path)
        i += 1

    exclusion_path = ""
    excl = form.get("exclusion_list")
    if excl and hasattr(excl, 'filename') and excl.filename:
        exclusion_path = await save_upload(excl, ALLOWED_SHEET, MAX_FILE, "exclusions")

    # ── Parse multi-selects ──
    def parse_json_field(key):
        val = form.get(key, "[]")
        try:
            return json.loads(str(val))
        except:
            return []

    industry = parse_json_field("industry")
    num_employees = parse_json_field("number_of_employees")
    job_level = parse_json_field("job_level")
    annual_revenue = parse_json_field("company_annual_revenue")
    try:
        max_leads_company = int(form.get("max_leads_per_company", 1))
    except:
        max_leads_company = 1

    notes = str(form.get("notes", "")).strip()
    mc_answer = str(form.get("multiple_choice_answer", "")).strip()

    slug = generate_submission_slug(company_name)

    conn = get_db()
    try:
        cursor = conn.execute("""INSERT INTO submissions (
            slug, created_at, company_name, contact_email, logo_path,
            company_website, whitepaper_title, whitepaper_paths, campaign_name,
            number_of_leads, start_date, end_date, exclusion_list_path,
            country, lead_distribution, industry, number_of_employees,
            job_level, max_leads_per_company, company_annual_revenue,
            notes, multiple_choice_answer, ip_address, user_agent, form_link_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            slug, datetime.now().isoformat(),
            company_name, contact_email, logo_path,
            company_website, str(form.get("whitepaper_title", "")).strip(),
            json.dumps(whitepaper_paths), campaign_name,
            number_of_leads, start_date, end_date, exclusion_path,
            country, str(form.get("lead_distribution", "")).strip(),
            json.dumps(industry), json.dumps(num_employees),
            json.dumps(job_level), max_leads_company, json.dumps(annual_revenue),
            notes, mc_answer, ip, request.headers.get("user-agent", ""),
            form_link_id
        ))
        submission_id = cursor.lastrowid

        # Update form_link status
        if form_link_id:
            conn.execute(
                "UPDATE form_links SET status='submitted', submitted_at=?, submission_id=? WHERE id=?",
                (datetime.now().isoformat(), submission_id, form_link_id)
            )

        conn.commit()
    except Exception as e:
        logger.error(f"DB error: {e}")
        raise HTTPException(500, "Server error. Your submission was not saved.")
    finally:
        conn.close()

    # ── Send email ──
    email_data = {
        "company_name": company_name, "contact_email": contact_email,
        "company_website": company_website,
        "whitepaper_title": str(form.get("whitepaper_title", "")).strip(),
        "campaign_name": campaign_name, "number_of_leads": str(number_of_leads),
        "start_date": start_date, "end_date": end_date,
        "country": country,
        "lead_distribution": str(form.get("lead_distribution", "")).strip(),
        "industry": industry, "number_of_employees": num_employees,
        "job_level": job_level, "max_leads_per_company": str(max_leads_company),
        "company_annual_revenue": annual_revenue,
        "notes": notes, "multiple_choice_answer": mc_answer
    }
    html = build_email_html(email_data)
    send_email(
        to_email=contact_email,
        cc_emails=CC_EMAILS,
        subject=f"ITdaily Lead Campaign Submission \u2013 {company_name}",
        html_body=html
    )

    return {"success": True, "slug": slug}

# ── CSV export ──────────────────────────────────────────────────────────
@app.get("/api/export")
async def export_csv(request: Request):
    require_auth(request)
    conn = get_db()
    rows = conn.execute("SELECT * FROM submissions ORDER BY created_at DESC").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow(tuple(row))
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=lead-submissions.csv"}
    )

@app.get("/api/export/{form_id}")
async def export_single(form_id: int, request: Request):
    require_auth(request)
    conn = get_db()
    fl = conn.execute("SELECT submission_id FROM form_links WHERE id=?", (form_id,)).fetchone()
    if not fl or not fl["submission_id"]:
        conn.close()
        raise HTTPException(404, "No submission found for this form")
    row = conn.execute("SELECT * FROM submissions WHERE id=?", (fl["submission_id"],)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Submission not found")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(row.keys())
    writer.writerow(tuple(row))
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=lead-{form_id}.csv"}
    )

# ═══════════════════════════════════════════════════════════════════════
# STATIC FILES & PAGE ROUTING
# ═══════════════════════════════════════════════════════════════════════

app.mount("/static", StaticFiles(directory="/app/static"), name="static")

@app.get("/login")
async def serve_login(request: Request):
    user = get_session_user(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return FileResponse("/app/static/login.html")

@app.get("/")
async def serve_dashboard(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return FileResponse("/app/static/dashboard.html")

@app.get("/{slug}")
async def serve_form_or_unavailable(slug: str):
    if slug in ("favicon.ico", "robots.txt"):
        raise HTTPException(404)
    conn = get_db()
    link = conn.execute("SELECT status FROM form_links WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if link and link["status"] == "pending":
        return FileResponse("/app/static/index.html")
    # Show unavailable page
    return HTMLResponse("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ITdaily. - Form Unavailable</title>
<link rel="icon" type="image/png" sizes="32x32" href="/static/favicon.png">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#111;color:#d4d4d4;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{text-align:center;padding:40px 24px;max-width:500px}
.logo{margin-bottom:32px}
.logo .it{fill:#f0f0f0}
.logo .daily{fill:#00D2D2}
h2{font-size:22px;color:#f0f0f0;margin-bottom:12px}
p{color:#707070;font-size:15px;line-height:1.6}
</style></head><body><div class="wrap">
<svg class="logo" width="180" viewBox="0 0 133 36" xmlns="http://www.w3.org/2000/svg">
<polygon class="it" points="12.6,4.7 12.6,0 0,0 0,4.7 3.6,4.7 3.6,24.1 0,24.1 0,28.8 12.6,28.8 12.6,24.1 9.1,24.1 9.1,4.7"/>
<path class="it" d="M16.3,4.7V0H36v4.7h-7.1v24.1h-5.5V4.7H16.3z"/>
<path class="daily" d="M37.9,18c0-1.6,0.2-3,0.5-4.4S39.3,11,40,10s1.6-1.8,2.7-2.4c1-0.6,2.3-0.9,3.7-0.9s2.7,0.3,3.7,0.9c1.1,0.6,1.9,1.4,2.6,2.5V0H58v28.8h-5.3v-2.9c-0.7,1.1-1.5,1.9-2.5,2.5s-2.2,0.9-3.7,0.9c-1.4,0-2.7-0.3-3.8-0.9S40.7,27,40,26s-1.3-2.2-1.6-3.6C38.1,21.1,37.9,19.6,37.9,18z M43.4,21.1c0,1.2,0.4,2.2,1.2,3s1.9,1.2,3.3,1.2c1.7,0,2.9-0.5,3.7-1.5s1.2-2.4,1.2-4.1v-3.2c0-1.7-0.4-3.1-1.2-4.1s-2-1.5-3.7-1.5c-1.4,0-2.5,0.4-3.3,1.2s-1.2,1.8-1.2,3C43.4,15.1,43.4,21.1,43.4,21.1z"/>
<path class="daily" d="M62.1,22.7c0-1.7,0.6-3.3,1.8-4.5c1.2-1.3,3-2,5.3-2.2l6-0.5V14c0-1.1-0.3-1.9-0.9-2.5c-0.6-0.5-1.4-0.8-2.5-0.8s-2,0.3-2.6,0.8c-0.7,0.5-1,1.3-1,2.3h-5.3c0-1.2,0.3-2.2,0.8-3.1s1.1-1.6,1.9-2.2s1.8-1,2.9-1.4c1.1-0.3,2.3-0.5,3.6-0.5c2.6,0,4.6,0.6,6.1,1.9s2.3,3.1,2.3,5.5v10.6H84v4.1h-8.3v-3.3h-0.2c-0.6,1.2-1.4,2.1-2.5,2.8c-1,0.7-2.4,1-4,1c-1,0-1.9-0.2-2.7-0.5s-1.5-0.8-2.2-1.4c-0.6-0.6-1.1-1.3-1.4-2.1C62.3,24.6,62.1,23.7,62.1,22.7z M67.6,23.3c0,0.6,0.3,1.1,0.9,1.5c0.6,0.3,1.4,0.5,2.3,0.5c1.4,0,2.4-0.5,3.2-1.4c0.8-1,1.2-2.1,1.2-3.5v-0.8L68.8,20c-0.8,0.1-1.2,0.6-1.2,1.4V23.3z"/>
<path class="daily" d="M86.6,4.7V0H92v4.7H86.6z M86.7,28.8V7.2H92v21.6H86.7z"/>
<polygon class="daily" points="102,24.7 102,0 96.7,0 96.7,28.8 105.6,28.8 105.6,24.7"/>
<path class="daily" d="M105.9,7.2h5.7l4.7,15.4h0.2l4.8-15.4h5.6L116.5,36h-9.2v-4.1h5.4l1.1-3.1L105.9,7.2z"/>
<path class="daily" d="M126.9,28.8v-6.1h6.1v6.1H126.9z"/>
</svg>
<h2>This form is no longer available</h2>
<p>The form link has expired or has already been submitted. Please contact us if you believe this is an error.</p>
</div></body></html>""", status_code=404)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
