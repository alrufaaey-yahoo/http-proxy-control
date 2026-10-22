from __future__ import annotations

import asyncio
import os
import ssl
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.sessions import SessionMiddleware

from .proxy import listener_callback
from .store import Store, password_matches

PANEL_USERNAME = os.getenv("PANEL_USERNAME", "")
PANEL_PASSWORD_HASH = os.getenv("PANEL_PASSWORD_HASH", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8443"))
PANEL_SSL_CERT = os.getenv("PANEL_SSL_CERT", "")
PANEL_SSL_KEY = os.getenv("PANEL_SSL_KEY", "")
store = Store()
store.initialize()
active: dict[int, asyncio.AbstractServer] = {}
login_attempts: dict[str, list[float]] = {}


class ListenerInput(BaseModel):
    port: int = Field(ge=1024, le=65535)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=3, max_length=256)
    tls_enabled: bool = False

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        if ":" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Username cannot contain colon or control characters")
        return value

    @field_validator("password")
    @classmethod
    def valid_password(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Password cannot contain control characters")
        return value


class ListenerUpdate(BaseModel):
    enabled: bool | None = None
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: str | None = Field(default=None, min_length=3, max_length=256)
    tls_enabled: bool | None = None

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str | None) -> str | None:
        if value is not None and (":" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("Username cannot contain colon or control characters")
        return value

    @field_validator("password")
    @classmethod
    def valid_password(cls, value: str | None) -> str | None:
        if value is not None and any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Password cannot contain control characters")
        return value


async def start_listener(listener: dict) -> None:
    listener_id = int(listener["id"])
    if listener_id in active:
        return
    tls_context = None
    if listener.get("tls_enabled", 1):
        if not PANEL_SSL_CERT or not PANEL_SSL_KEY:
            raise OSError("TLS certificate is not configured")
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(PANEL_SSL_CERT, PANEL_SSL_KEY)
    server = await asyncio.start_server(
        listener_callback(listener["username"], listener["password_hash"]),
        host="0.0.0.0", port=int(listener["port"]), limit=65536,
        start_serving=True, ssl=tls_context,
    )
    active[listener_id] = server


async def stop_listener(listener_id: int) -> None:
    server = active.pop(listener_id, None)
    if server:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    for listener in store.list_listeners():
        if listener["enabled"]:
            full = store.get_listener(listener["id"])
            try:
                await start_listener(full)
            except OSError:
                store.set_enabled(listener["id"], False)
    yield
    for listener_id in list(active):
        await stop_listener(listener_id)


app = FastAPI(title="HTTP Proxy Control", version="1.0.0", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET or "development-only-change-me",
                   session_cookie="proxy_panel_session", same_site="strict", https_only=False,
                   max_age=8 * 60 * 60)


@app.middleware("http")
async def security_headers_and_origin(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if not origin:
            return JSONResponse({"detail": "Origin header required"}, status_code=403)
        parsed = urlsplit(origin)
        if parsed.netloc.lower() != request.headers.get("host", "").lower():
            return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


def require_login(request: Request) -> None:
    if request.session.get("user") != PANEL_USERNAME:
        raise HTTPException(status_code=401, detail="Login required")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if request.session.get("user") != PANEL_USERNAME:
        return HTMLResponse(LOGIN_HTML)
    return HTMLResponse(PANEL_HTML)


@app.post("/api/login")
async def login(request: Request):
    if not PANEL_USERNAME or not PANEL_PASSWORD_HASH or not SESSION_SECRET:
        raise HTTPException(status_code=503, detail="Panel credentials are not configured")
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [t for t in login_attempts.get(ip, []) if now - t < 300]
    if len(attempts) >= 5:
        login_attempts[ip] = attempts
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in five minutes.")
    try:
        data = await request.json()
        username, password = data.get("username", ""), data.get("password", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request")
    if not isinstance(username, str) or not isinstance(password, str) or username != PANEL_USERNAME or not password_matches(password, PANEL_PASSWORD_HASH):
        attempts.append(now)
        login_attempts[ip] = attempts
        raise HTTPException(status_code=401, detail="Invalid username or password")
    login_attempts.pop(ip, None)
    request.session.clear()
    request.session["user"] = PANEL_USERNAME
    return {"ok": True}


@app.post("/api/logout")
async def logout(request: Request):
    require_login(request)
    request.session.clear()
    return {"ok": True}


@app.get("/api/listeners")
async def list_listeners(request: Request):
    require_login(request)
    items = store.list_listeners()
    hostname = request.url.hostname or "SERVER_IP"
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    for item in items:
        item["running"] = item["id"] in active
        scheme = "https" if item["tls_enabled"] else "http"
        item["address"] = f"{scheme}://{hostname}:{item['port']}"
    return {"listeners": items}


@app.post("/api/listeners")
async def create_listener(payload: ListenerInput, request: Request):
    require_login(request)
    if payload.port == PANEL_PORT:
        raise HTTPException(status_code=400, detail="Proxy port must differ from the panel port")
    if store.get_listener_by_port(payload.port):
        raise HTTPException(status_code=409, detail="This port is already configured")
    try:
        listener_id = store.create_listener(payload.port, payload.username, payload.password, payload.tls_enabled)
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Could not save listener") from exc
    listener = store.get_listener(listener_id)
    try:
        await start_listener(listener)
    except OSError as exc:
        store.delete_listener(listener_id)
        raise HTTPException(status_code=409, detail=f"Could not bind to port {payload.port}: {exc.strerror or 'port unavailable'}")
    return {"ok": True, "id": listener_id}


@app.patch("/api/listeners/{listener_id}")
async def update_listener(listener_id: int, payload: ListenerUpdate, request: Request):
    require_login(request)
    listener = store.get_listener(listener_id)
    if not listener:
        raise HTTPException(status_code=404, detail="Listener not found")
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    target_tls = fields.get("tls_enabled", bool(listener["tls_enabled"]))
    if target_tls and (not PANEL_SSL_CERT or not PANEL_SSL_KEY):
        raise HTTPException(status_code=409, detail="TLS certificate is not configured on this server")
    username = fields.get("username", listener["username"])
    password = fields.get("password")
    config_changed = any(key in fields for key in ("username", "password", "tls_enabled"))
    if config_changed:
        await stop_listener(listener_id)
    if "username" in fields or password:
        store.update_credentials(listener_id, username, password)
    if "tls_enabled" in fields:
        store.set_tls_enabled(listener_id, bool(fields["tls_enabled"]))
    enabled = fields.get("enabled", bool(listener["enabled"]))
    if not enabled:
        await stop_listener(listener_id)
        store.set_enabled(listener_id, False)
    elif config_changed or not listener_id in active:
        fresh = store.get_listener(listener_id)
        try:
            await start_listener(fresh)
        except OSError as exc:
            store.set_enabled(listener_id, False)
            raise HTTPException(status_code=409, detail=f"Could not start listener: {exc.strerror or str(exc) or 'listener configuration invalid'}")
        store.set_enabled(listener_id, True)
    return {"ok": True}


@app.delete("/api/listeners/{listener_id}")
async def delete_listener(listener_id: int, request: Request):
    require_login(request)
    if not store.get_listener(listener_id):
        raise HTTPException(status_code=404, detail="Listener not found")
    await stop_listener(listener_id)
    store.delete_listener(listener_id)
    return {"ok": True}


LOGIN_HTML = r'''<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>تسجيل الدخول | Proxy Control</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e8eef9;font-family:system-ui,Arial;min-height:100vh;display:grid;place-items:center}.card{width:min(420px,92vw);padding:32px;background:#121d30;border:1px solid #253653;border-radius:18px;box-shadow:0 20px 60px #0006}h1{margin:0 0 8px}p{color:#aebbd0}label{display:block;margin:18px 0 7px}input{width:100%;padding:12px;border-radius:9px;border:1px solid #344763;background:#0c1628;color:white;font-size:16px}button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:9px;background:#5b8cff;color:#fff;font-weight:700;font-size:16px;cursor:pointer}.error{color:#ff9797;min-height:24px}.small{font-size:13px;line-height:1.6}</style></head><body><main class="card"><h1>لوحة إدارة الوكيل</h1><p>سجّل الدخول لإدارة منافذ HTTP/HTTPS Proxy.</p><form id="login"><label for="u">اسم المستخدم</label><input id="u" autocomplete="username" required><label for="p">كلمة المرور</label><input id="p" type="password" autocomplete="current-password" required><button>دخول آمن</button><div id="error" class="error" role="alert"></div></form><p class="small">استخدم HTTPS. شهادة التثبيت الافتراضية ذاتية التوقيع؛ تحقّق من عنوان الخادم قبل المتابعة.</p></main><script>document.querySelector('#login').onsubmit=async e=>{e.preventDefault();let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.querySelector('#u').value,password:document.querySelector('#p').value})});if(r.ok)location.reload();else document.querySelector('#error').textContent=(await r.json()).detail||'تعذر تسجيل الدخول';};</script></body></html>'''

PANEL_HTML = r'''<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Control</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e8eef9;font-family:system-ui,Arial}.wrap{max-width:1100px;margin:auto;padding:28px 18px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{margin:0}.sub{color:#aebbd0;margin:8px 0 24px}.box{background:#121d30;border:1px solid #253653;border-radius:16px;padding:20px;margin:16px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}label{display:block;margin:5px 0 7px;color:#c3cee0}input{width:100%;padding:11px;border-radius:8px;border:1px solid #344763;background:#0c1628;color:white;font-size:15px}button{padding:10px 15px;border:0;border-radius:8px;background:#5b8cff;color:white;font-weight:650;cursor:pointer}button.secondary{background:#283b57}button.danger{background:#9b3d4c}button:disabled{opacity:.5}form button{margin-top:14px}.notice{padding:12px;border-radius:9px;background:#202f48;color:#c8d7ef;line-height:1.7}.error{color:#ff9797;min-height:24px}.table{overflow:auto}table{width:100%;border-collapse:collapse;min-width:660px}td,th{text-align:right;padding:13px;border-bottom:1px solid #263651}th{color:#afc1dc}.badge{padding:4px 9px;border-radius:999px;background:#174b3d;color:#9bf0cb}.off{background:#4d3d1c;color:#ffdc88}.actions{display:flex;gap:8px;flex-wrap:wrap}.muted{color:#aebbd0;font-size:13px}.check{display:flex;align-items:center;gap:9px;margin-top:30px}.check input{width:auto;transform:scale(1.15)}code{direction:ltr;display:inline-block;background:#09111e;padding:3px 6px;border-radius:5px}@media(max-width:600px){.wrap{padding:18px 12px}.box{padding:15px}}</style></head><body><main class="wrap"><div class="top"><h1>إدارة HTTP/HTTPS Proxy</h1><button class="secondary" onclick="logout()">تسجيل الخروج</button></div><p class="sub">أنشئ وأدر مستمعات الوكيل؛ كل منفذ له بيانات دخول مستقلة. HTTP العادي هو الافتراضي لتوافق المتصفحات؛ TLS اختياري.</p><div class="notice">الأمان: المنافذ تُربط على <code>0.0.0.0</code> لتكون متاحة من الإنترنت. استخدم HTTP العادي عند إعداد المتصفح كـ HTTP Proxy؛ سيعمل HTTPS للمواقع عبر CONNECT. فعّل TLS فقط إذا كان عميلك يدعم HTTPS Proxy وضُبط على ذلك. كلمة المرور عبر HTTP غير مشفرة؛ استخدم TLS أو شبكة موثوقة، وافتح المنفذ في جدار الحماية. عنوان لوحة Sandbox/Preview ليس عنوان VPS ولا يمرر منافذ Proxy الإضافية.</div><section class="box"><h2>إضافة منفذ Proxy</h2><form id="create"><div class="grid"><div><label>المنفذ (1024–65535)</label><input id="port" type="number" min="1024" max="65535" required placeholder="مثال: 18080"></div><div><label>اسم مستخدم الوكيل</label><input id="username" maxlength="64" required></div><div><label>كلمة مرور الوكيل (3 أحرف على الأقل؛ اختر أطول للأمان)</label><input id="password" type="password" minlength="3" autocomplete="new-password" required></div><div class="check"><input id="tls" type="checkbox"><label for="tls">TLS بين العميل والوكيل (اختياري؛ يحتاج دعم HTTPS Proxy)</label></div></div><button>إنشاء وتشغيل المنفذ</button><div id="error" class="error"></div></form></section><section class="box"><h2>المنافذ المُدارة</h2><div class="table"><table><thead><tr><th>العنوان</th><th>اسم المستخدم</th><th>الحالة</th><th>أُنشئ في</th><th>إجراءات</th></tr></thead><tbody id="rows"></tbody></table></div><p id="empty" class="muted"></p></section><p class="muted">لإعداد المتصفح المعتاد اختر HTTP Proxy، ثم أدخل IP أو نطاق VPS والمنفذ وبيانات الدخول؛ HTTPS للمواقع يعمل عبر CONNECT. إذا فعّلت TLS فاختر HTTPS Proxy في العميل. لا تستخدم رابط Preview/Sandbox أو منفذ لوحة التحكم كعنوان Proxy؛ استخدم VPS وافتح منفذ Proxy في جدار الحماية. كلمات المرور لا يمكن عرضها بعد حفظها.</p></main><script>
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function api(url,method='GET',body){let r=await fetch(url,{method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});let d=await r.json().catch(()=>({}));if(r.status===401){location.reload();throw Error('انتهت الجلسة')}if(!r.ok)throw Error(d.detail||'حدث خطأ');return d}
async function refresh(){let {listeners}=await api('/api/listeners');let rows=document.querySelector('#rows');rows.innerHTML='';document.querySelector('#empty').textContent=listeners.length?'':'لا توجد منافذ بعد.';for(let x of listeners){let tr=document.createElement('tr');tr.innerHTML=`<td><code>${esc(x.address)}</code></td><td>${esc(x.username)}</td><td><span class="badge ${x.running?'':'off'}">${x.running?'يعمل':'متوقف'}</span></td><td>${esc(x.created_at)}</td><td><div class="actions"><button class="secondary" onclick="toggle(${x.id},${!x.enabled})">${x.enabled?'إيقاف':'تشغيل'}</button><button class="secondary" onclick="setTls(${x.id},${!x.tls_enabled})">${x.tls_enabled?'تحويل إلى HTTP':'تفعيل TLS'}</button><button class="secondary" onclick="credentials(${x.id})">تغيير بيانات الدخول</button><button class="danger" onclick="removeListener(${x.id})">حذف</button></div></td>`;rows.appendChild(tr)}}
document.querySelector('#create').onsubmit=async e=>{e.preventDefault();let er=document.querySelector('#error');er.textContent='';try{await api('/api/listeners','POST',{port:Number(document.querySelector('#port').value),username:document.querySelector('#username').value,password:document.querySelector('#password').value,tls_enabled:document.querySelector('#tls').checked});e.target.reset();await refresh()}catch(x){er.textContent=x.message}};
async function toggle(id,enabled){try{await api('/api/listeners/'+id,'PATCH',{enabled});await refresh()}catch(e){alert(e.message)}}async function setTls(id,tls_enabled){let msg=tls_enabled?'تفعيل TLS؟ تأكد أن عميلك مضبوط على HTTPS Proxy وأن شهادة الخادم موثوقة.':'إيقاف TLS واستخدام HTTP Proxy القياسي؟';if(!confirm(msg))return;try{await api('/api/listeners/'+id,'PATCH',{tls_enabled});await refresh()}catch(e){alert(e.message)}}async function credentials(id){let username=prompt('اسم المستخدم الجديد:');if(username===null)return;let password=prompt('كلمة مرور جديدة (3 أحرف على الأقل؛ اتركها فارغة للإبقاء على الحالية):');if(password===null)return;try{await api('/api/listeners/'+id,'PATCH',{username,password:password||undefined});await refresh()}catch(e){alert(e.message)}}async function removeListener(id){if(!confirm('حذف هذا المنفذ نهائيًا؟'))return;try{await api('/api/listeners/'+id,'DELETE');await refresh()}catch(e){alert(e.message)}}async function logout(){await api('/api/logout','POST',{});location.reload()}refresh().catch(e=>document.querySelector('#rows').textContent=e.message);
</script></body></html>'''
