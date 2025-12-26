import os
import secrets
import sqlite3
import time
import base64
import hashlib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
import jwt
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


DATA_DIR = os.environ.get("APP_DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "keda.db")


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


APP_CORS_MODE = os.environ.get("APP_CORS_MODE", "secure").strip().lower()
APP_ERROR_DETAIL = env_bool("APP_ERROR_DETAIL", False)
APP_AUTHZ_ENFORCE_TENANT = env_bool("APP_AUTHZ_ENFORCE_TENANT", True)
APP_AUTHZ_ENFORCE_OWNER = env_bool("APP_AUTHZ_ENFORCE_OWNER", True)
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8080")

OIDC_ENABLED = env_bool("OIDC_ENABLED", False)
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "keda-app")
OIDC_ISSUER_PUBLIC = os.environ.get("OIDC_ISSUER_PUBLIC", "http://localhost:8081/realms/keda")
OIDC_ISSUER_INTERNAL = os.environ.get("OIDC_ISSUER_INTERNAL", "http://keycloak:8080/realms/keda")


def ensure_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL,
              tenant TEXT NOT NULL,
              role TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant TEXT NOT NULL,
              owner_user_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              body TEXT NOT NULL,
              created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER NOT NULL,
              request_id TEXT NOT NULL,
              user_id INTEGER,
              action TEXT NOT NULL,
              detail TEXT NOT NULL
            )
            """
        )
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            conn.executemany(
                "INSERT INTO users (username,password,tenant,role) VALUES (?,?,?,?)",
                [
                    ("alice", "alice", "tenant-a", "user"),
                    ("bob", "bob", "tenant-a", "admin"),
                    ("carol", "carol", "tenant-b", "user"),
                ],
            )
            conn.executemany(
                "INSERT INTO items (tenant,owner_user_id,title,body,created_at) VALUES (?,?,?,?,?)",
                [
                    ("tenant-a", 1, "alice note", "hello from alice", int(time.time())),
                    ("tenant-a", 2, "bob note", "admin note", int(time.time())),
                    ("tenant-b", 3, "carol note", "hello from carol", int(time.time())),
                ],
            )


@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    tenant: str
    role: str


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def audit(conn: sqlite3.Connection, request_id: str, user_id: int | None, action: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO audit_events (ts,request_id,user_id,action,detail) VALUES (?,?,?,?,?)",
        (int(time.time()), request_id, user_id, action, detail),
    )


def get_request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id")
    if rid:
        return rid[:128]
    return secrets.token_urlsafe(12)


def require_user(request: Request) -> CurrentUser:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return CurrentUser(**user)


def can_access_item(user: CurrentUser, item: sqlite3.Row) -> bool:
    if APP_AUTHZ_ENFORCE_TENANT and item["tenant"] != user.tenant:
        return False
    if user.role == "admin":
        return True
    if APP_AUTHZ_ENFORCE_OWNER and item["owner_user_id"] != user.id:
        return False
    return True


app = FastAPI(debug=APP_ERROR_DETAIL)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("APP_SESSION_SECRET", "dev-secret"))

if APP_CORS_MODE == "wildcard":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
elif APP_CORS_MODE == "reflect":
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[APP_BASE_URL],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )


@app.on_event("startup")
def _startup() -> None:
    ensure_db()


@app.middleware("http")
async def add_request_id_header(request: Request, call_next) -> Response:
    request_id = get_request_id(request)
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        oidc_link = '<li><a href="/oidc/login">OIDC login (Keycloak)</a></li>' if OIDC_ENABLED else ""
        return """
        <h1>keda-app</h1>
        <p>Not logged in.</p>
        <ul>
          <li><a href="/login">Local login</a></li>
        """
        + oidc_link
        + """
        </ul>
        """
    return f"""
    <h1>keda-app</h1>
    <p>Logged in as <b>{user["username"]}</b> ({user["role"]}, {user["tenant"]})</p>
    <ul>
      <li><a href="/me">/me</a></li>
      <li><a href="/ui/items">items UI</a></li>
      <li><a href="/admin/audit">audit (admin only)</a></li>
    </ul>
    <form method="post" action="/logout"><button>logout</button></form>
    """


@app.get("/login", response_class=HTMLResponse)
def login_form() -> str:
    return """
    <h1>Local login</h1>
    <form method="post" action="/login">
      <label>username <input name="username" /></label><br/>
      <label>password <input name="password" type="password" /></label><br/>
      <button>login</button>
    </form>
    <p>Seed users: alice/alice (tenant-a user), bob/bob (tenant-a admin), carol/carol (tenant-b user)</p>
    """


def _oidc_endpoints(issuer: str) -> dict[str, str]:
    return {
        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
    }


def _base64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@app.get("/oidc/login")
def oidc_login(request: Request) -> Response:
    if not OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="oidc disabled")

    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = _base64url_no_pad(hashlib.sha256(code_verifier.encode()).digest())

    request.session["oidc"] = {"state": state, "code_verifier": code_verifier}

    redirect_uri = f"{APP_BASE_URL}/oidc/callback"
    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{_oidc_endpoints(OIDC_ISSUER_PUBLIC)['authorization_endpoint']}?{urlencode(params)}"
    return RedirectResponse(url, status_code=302)


@app.get("/oidc/callback")
def oidc_callback(request: Request, code: str | None = None, state: str | None = None) -> Response:
    if not OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="oidc disabled")
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code/state")

    saved = request.session.get("oidc") or {}
    if saved.get("state") != state:
        raise HTTPException(status_code=400, detail="state mismatch")

    redirect_uri = f"{APP_BASE_URL}/oidc/callback"
    token_endpoint = _oidc_endpoints(OIDC_ISSUER_INTERNAL)["token_endpoint"]
    data = {
        "grant_type": "authorization_code",
        "client_id": OIDC_CLIENT_ID,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": saved.get("code_verifier", ""),
    }

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(token_endpoint, data=data)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="token exchange failed")
        token = resp.json()

    id_token = token.get("id_token")
    if not id_token:
        raise HTTPException(status_code=502, detail="missing id_token")

    claims = jwt.decode(id_token, options={"verify_signature": False, "verify_aud": False})
    username = claims.get("preferred_username") or claims.get("email") or "oidc-user"

    request_id = get_request_id(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (username,password,tenant,role) VALUES (?,?,?,?)",
                (username, secrets.token_urlsafe(24), "tenant-a", "user"),
            )
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        request.session["user"] = {
            "id": int(row["id"]),
            "username": row["username"],
            "tenant": row["tenant"],
            "role": row["role"],
        }
        audit(conn, request_id, int(row["id"]), "login_ok", "oidc")

    request.session.pop("oidc", None)
    return RedirectResponse("/", status_code=303)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)) -> Response:
    request_id = get_request_id(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or row["password"] != password:
            audit(conn, request_id, None, "login_failed", f"username={username}")
            raise HTTPException(status_code=401, detail="invalid credentials")
        request.session["user"] = {
            "id": int(row["id"]),
            "username": row["username"],
            "tenant": row["tenant"],
            "role": row["role"],
        }
        audit(conn, request_id, int(row["id"]), "login_ok", "local")
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/me")
def me(user: CurrentUser = Depends(require_user)) -> dict[str, Any]:
    return {"id": user.id, "username": user.username, "tenant": user.tenant, "role": user.role}


@app.get("/api/items")
def list_items(user: CurrentUser = Depends(require_user)) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM items ORDER BY id").fetchall()
        visible = [dict(r) for r in rows if can_access_item(user, r)]
    return visible


@app.get("/api/items/{item_id}")
def get_item(item_id: int, user: CurrentUser = Depends(require_user)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not can_access_item(user, row):
            raise HTTPException(status_code=403, detail="forbidden")
        return dict(row)


@app.post("/api/items")
def create_item(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
    user: CurrentUser = Depends(require_user),
) -> dict[str, Any]:
    request_id = get_request_id(request)
    with db() as conn:
        conn.execute(
            "INSERT INTO items (tenant,owner_user_id,title,body,created_at) VALUES (?,?,?,?,?)",
            (user.tenant, user.id, title, body, int(time.time())),
        )
        item_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        audit(conn, request_id, user.id, "item_create", f"item_id={item_id}")
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        return dict(row)


@app.patch("/api/items/{item_id}")
def update_item(
    request: Request,
    item_id: int,
    title: str = Form(None),
    body: str = Form(None),
    user: CurrentUser = Depends(require_user),
) -> dict[str, Any]:
    request_id = get_request_id(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not can_access_item(user, row):
            raise HTTPException(status_code=403, detail="forbidden")
        new_title = title if title is not None else row["title"]
        new_body = body if body is not None else row["body"]
        conn.execute("UPDATE items SET title = ?, body = ? WHERE id = ?", (new_title, new_body, item_id))
        audit(conn, request_id, user.id, "item_update", f"item_id={item_id}")
        updated = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        return dict(updated)


@app.get("/ui/items", response_class=HTMLResponse)
def items_ui(user: CurrentUser = Depends(require_user)) -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM items ORDER BY id").fetchall()
        visible = [r for r in rows if can_access_item(user, r)]

    items_html = "".join(
        f"<li>#{r['id']} tenant={r['tenant']} owner={r['owner_user_id']} <b>{r['title']}</b> : {r['body']}</li>"
        for r in visible
    )
    return f"""
    <h1>Items</h1>
    <p>user={user.username} ({user.role}, {user.tenant})</p>
    <ul>{items_html}</ul>
    <h2>Create</h2>
    <form method="post" action="/ui/items/create">
      <label>title <input name="title"/></label><br/>
      <label>body <input name="body"/></label><br/>
      <button>create</button>
    </form>
    <p><a href="/">home</a></p>
    """


@app.post("/ui/items/create")
def items_ui_create(request: Request, title: str = Form(...), body: str = Form(...), user: CurrentUser = Depends(require_user)) -> Response:
    _ = create_item(request=request, title=title, body=body, user=user)
    return RedirectResponse("/ui/items", status_code=303)


@app.get("/admin/audit", response_class=HTMLResponse)
def audit_ui(user: CurrentUser = Depends(require_user)) -> str:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 50").fetchall()
    rows_html = "".join(
        f"<li>#{r['id']} ts={r['ts']} rid={r['request_id']} user_id={r['user_id']} action={r['action']} detail={r['detail']}</li>"
        for r in rows
    )
    return f"""
    <h1>Audit events (latest 50)</h1>
    <ul>{rows_html}</ul>
    <p><a href="/">home</a></p>
    """
