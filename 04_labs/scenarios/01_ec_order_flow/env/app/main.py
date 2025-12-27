import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


DATA_DIR = os.environ.get("APP_DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "keda_ec.db")
SEED_SQL_PATH = os.path.join(os.path.dirname(__file__), "db_seed.sql")


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
            CREATE TABLE IF NOT EXISTS products (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sku TEXT NOT NULL,
              name TEXT NOT NULL,
              price INTEGER NOT NULL,
              stock INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant TEXT NOT NULL,
              buyer_user_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              quantity INTEGER NOT NULL,
              total INTEGER NOT NULL,
              status TEXT NOT NULL,
              note TEXT NOT NULL,
              flag TEXT,
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
        if existing == 0 and os.path.exists(SEED_SQL_PATH):
            with open(SEED_SQL_PATH, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
        elif existing == 0:
            conn.execute(
                "INSERT INTO users (username,password,tenant,role) VALUES (?,?,?,?)",
                ("alice", "alice", "tenant-a", "user"),
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


def can_access_order(user: CurrentUser, order: sqlite3.Row) -> bool:
    if APP_AUTHZ_ENFORCE_TENANT and order["tenant"] != user.tenant:
        return False
    if user.role == "admin":
        return True
    if APP_AUTHZ_ENFORCE_OWNER and order["buyer_user_id"] != user.id:
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
        allow_methods=["GET", "POST"],
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
        return """
        <style>
          :root { --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }
          body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
                 background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
                 color: var(--text); }
          .wrap { max-width: 860px; margin: 48px auto; padding: 0 20px; }
          .card { background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 24px; }
          .btn { display:inline-block; padding: 12px 16px; border-radius: 10px; background: #0ea5e9;
                 color: #fff; text-decoration: none; font-weight: 600; }
          .muted { color: var(--muted); }
        </style>
        <div class="wrap">
          <div class="card">
            <h1 style="margin:0 0 8px;">KedaMart</h1>
            <p class="muted">未ログイン。注文フローを観測するためログインしてください。</p>
            <a class="btn" href="/login">ローカルログイン</a>
          </div>
        </div>
        """
    return f"""
    <style>
      :root {{ --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }}
      body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
             color: var(--text); }}
      .wrap {{ max-width: 980px; margin: 40px auto; padding: 0 20px; }}
      .card {{ background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 20px; }}
      .row {{ display:flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
      .btn {{ display:inline-block; padding: 10px 14px; border-radius: 10px; background: #0ea5e9;
             color: #fff; text-decoration: none; font-weight: 600; }}
      .btn.ghost {{ background: transparent; border: 1px solid #334155; color: var(--text); }}
      .muted {{ color: var(--muted); }}
    </style>
    <div class="wrap">
      <div class="card">
        <h1 style="margin:0 0 6px;">KedaMart</h1>
        <p class="muted">ログイン中: <b>{user["username"]}</b>（{user["role"]}, {user["tenant"]}）</p>
        <div class="row">
          <a class="btn" href="/ui/products">商品一覧</a>
          <a class="btn ghost" href="/ui/orders">注文一覧</a>
          <a class="btn ghost" href="/admin/audit">監査ログ（管理者のみ）</a>
          <form method="post" action="/logout"><button class="btn ghost" type="submit">ログアウト</button></form>
        </div>
      </div>
    </div>
    """


@app.get("/login", response_class=HTMLResponse)
def login_form() -> str:
    return """
    <style>
      :root { --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }
      body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
             color: var(--text); }
      .wrap { max-width: 520px; margin: 48px auto; padding: 0 20px; }
      .card { background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 24px; }
      label { display:block; margin: 10px 0 6px; }
      input { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #374151;
              background: #0f172a; color: var(--text); }
      .btn { margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: #0ea5e9;
             color: #fff; border: none; font-weight: 600; }
      .muted { color: var(--muted); font-size: 13px; }
    </style>
    <div class="wrap">
      <div class="card">
        <h1 style="margin:0 0 6px;">ローカルログイン</h1>
        <p class="muted">教材用の固定ユーザーでログインします。</p>
        <form method="post" action="/login">
          <label>ユーザー名</label>
          <input name="username" />
          <label>パスワード</label>
          <input name="password" type="password" />
          <button class="btn">ログイン</button>
        </form>
        <p class="muted">初期ユーザー: alice/alice（tenant-a, user） / bob/bob（tenant-a, admin） / carol/carol（tenant-b, user）</p>
      </div>
    </div>
    """


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


@app.get("/api/products")
def api_products(user: CurrentUser = Depends(require_user)) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM products ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/orders")
def api_orders(user: CurrentUser = Depends(require_user)) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM orders ORDER BY id").fetchall()
        visible = [dict(r) for r in rows if can_access_order(user, r)]
    return visible


@app.get("/api/orders/{order_id}")
def api_order(order_id: int, user: CurrentUser = Depends(require_user)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not can_access_order(user, row):
            raise HTTPException(status_code=403, detail="forbidden")
        return dict(row)


@app.post("/api/orders")
def api_create_order(
    request: Request,
    product_id: int = Form(...),
    quantity: int = Form(...),
    user: CurrentUser = Depends(require_user),
) -> dict[str, Any]:
    request_id = get_request_id(request)
    with db() as conn:
        product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not product:
            raise HTTPException(status_code=400, detail="invalid product")
        total = product["price"] * quantity
        conn.execute(
            """
            INSERT INTO orders (tenant,buyer_user_id,product_id,quantity,total,status,note,flag,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (user.tenant, user.id, product_id, quantity, total, "pending", "standard delivery", None, int(time.time())),
        )
        order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        audit(conn, request_id, user.id, "order_create", f"order_id={order_id}")
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        return dict(row)


@app.post("/api/orders/{order_id}/pay")
def api_pay_order(request: Request, order_id: int, user: CurrentUser = Depends(require_user)) -> dict[str, Any]:
    request_id = get_request_id(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not can_access_order(user, row):
            raise HTTPException(status_code=403, detail="forbidden")
        conn.execute("UPDATE orders SET status = ? WHERE id = ?", ("paid", order_id))
        audit(conn, request_id, user.id, "order_pay", f"order_id={order_id}")
        updated = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        return dict(updated)


@app.get("/ui/products", response_class=HTMLResponse)
def ui_products(user: CurrentUser = Depends(require_user)) -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM products ORDER BY id").fetchall()
    items = "".join(
        f"<li><b>{r['name']}</b> / {r['sku']} / {r['price']}円 / 在庫 {r['stock']}</li>"
        for r in rows
    )
    return f"""
    <style>
      :root {{ --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }}
      body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
             color: var(--text); }}
      .wrap {{ max-width: 980px; margin: 40px auto; padding: 0 20px; }}
      .card {{ background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 20px; }}
      .muted {{ color: var(--muted); }}
      input {{ padding: 8px 10px; border-radius: 10px; border: 1px solid #374151;
               background: #0f172a; color: var(--text); }}
      .btn {{ padding: 8px 12px; border-radius: 10px; background: #0ea5e9; color: #fff; border: none; }}
      ul {{ list-style: none; padding-left: 0; }}
      li {{ padding: 10px 0; border-bottom: 1px dashed #334155; }}
    </style>
    <div class="wrap">
      <div class="card">
        <h1 style="margin:0 0 6px;">商品一覧</h1>
        <p class="muted">ユーザー={user.username}（{user.role}, {user.tenant}）</p>
        <ul>{items}</ul>
      </div>
      <div class="card" style="margin-top:16px;">
        <h2 style="margin:0 0 8px;">注文作成</h2>
        <form method="post" action="/ui/orders/create">
          <label>商品ID</label><br/>
          <input name="product_id"/><br/><br/>
          <label>数量</label><br/>
          <input name="quantity"/><br/><br/>
          <button class="btn">注文する</button>
        </form>
      </div>
      <p style="margin-top:14px;"><a href="/" style="color:#93c5fd;">ホーム</a></p>
    </div>
    """


@app.get("/ui/orders", response_class=HTMLResponse)
def ui_orders(user: CurrentUser = Depends(require_user)) -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM orders ORDER BY id").fetchall()
        visible = [r for r in rows if can_access_order(user, r)]
    items = "".join(
        f"<li>#{r['id']} buyer={r['buyer_user_id']} product={r['product_id']} qty={r['quantity']} total={r['total']} status={r['status']}</li>"
        for r in visible
    )
    return f"""
    <style>
      :root {{ --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }}
      body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
             color: var(--text); }}
      .wrap {{ max-width: 980px; margin: 40px auto; padding: 0 20px; }}
      .card {{ background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 20px; }}
      .muted {{ color: var(--muted); }}
      ul {{ list-style: none; padding-left: 0; }}
      li {{ padding: 10px 0; border-bottom: 1px dashed #334155; }}
    </style>
    <div class="wrap">
      <div class="card">
        <h1 style="margin:0 0 6px;">注文一覧</h1>
        <p class="muted">ユーザー={user.username}（{user.role}, {user.tenant}）</p>
        <ul>{items}</ul>
      </div>
      <p style="margin-top:14px;"><a href="/" style="color:#93c5fd;">ホーム</a></p>
    </div>
    """


@app.post("/ui/orders/create")
def ui_create_order(
    request: Request,
    product_id: int = Form(...),
    quantity: int = Form(...),
    user: CurrentUser = Depends(require_user),
) -> Response:
    _ = api_create_order(request=request, product_id=product_id, quantity=quantity, user=user)
    return RedirectResponse("/ui/orders", status_code=303)


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
    <style>
      :root {{ --bg:#0b0f1a; --card:#111827; --muted:#9ca3af; --text:#e5e7eb; }}
      body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: radial-gradient(1200px 600px at 10% 10%, #1f2937, #0b0f1a 60%);
             color: var(--text); }}
      .wrap {{ max-width: 980px; margin: 40px auto; padding: 0 20px; }}
      .card {{ background: var(--card); border: 1px solid #1f2937; border-radius: 16px; padding: 20px; }}
      .muted {{ color: var(--muted); }}
      ul {{ list-style: none; padding-left: 0; }}
      li {{ padding: 10px 0; border-bottom: 1px dashed #334155; }}
    </style>
    <div class="wrap">
      <div class="card">
        <h1 style="margin:0 0 8px;">監査イベント（最新50件）</h1>
        <p class="muted">相関ID（rid）でログの追跡ができます。</p>
        <ul>{rows_html}</ul>
      </div>
      <p style="margin-top:14px;"><a href="/" style="color:#93c5fd;">ホーム</a></p>
    </div>
    """
