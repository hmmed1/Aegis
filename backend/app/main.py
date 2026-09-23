"""
Aegis central server.

Route guard: every request is checked by AuthGuardMiddleware. Unauthenticated
browser requests to anything except /login are redirected to /login.
Unauthenticated calls to protected JSON APIs get a 401. Sensor ingest
endpoints are exempt from the user-session check -- they authenticate with
their own per-sensor X-Sensor-Key instead.
"""
import logging
import sys

from fastapi import FastAPI, Request, Response, Depends, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from .config import settings
from .security import hash_password, verify_password, create_session_token, decode_session_token
from .store import store

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("aegis")

app = FastAPI(title="Aegis")
templates = Jinja2Templates(directory="app/templates")

# ---------------------------------------------------------------------------
# Admin credential bootstrap
# ---------------------------------------------------------------------------
if settings.ADMIN_PASSWORD:
    _ADMIN_HASH = hash_password(settings.ADMIN_PASSWORD)
else:
    import secrets as _secrets
    _generated = _secrets.token_urlsafe(12)
    _ADMIN_HASH = hash_password(_generated)
    log.warning(
        "No ADMIN_PASSWORD set. Generated a one-time password for user "
        "'%s': %s -- set ADMIN_PASSWORD in your .env for a persistent login.",
        settings.ADMIN_USERNAME,
        _generated,
    )

# ---------------------------------------------------------------------------
# Route guard middleware
# ---------------------------------------------------------------------------
PUBLIC_PATHS = {"/login", "/favicon.ico"}
PUBLIC_API_PATHS = {"/api/v1/auth/login"}
PUBLIC_PREFIXES = ("/static/", "/api/v1/ingest/")


class AuthGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        is_public = (
            path in PUBLIC_PATHS
            or path in PUBLIC_API_PATHS
            or path.startswith(PUBLIC_PREFIXES)
        )

        if is_public:
            return await call_next(request)

        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        username = decode_session_token(token) if token else None

        if not username:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not authenticated"}, status_code=401)
            return RedirectResponse(url="/login", status_code=303)

        request.state.username = username
        return await call_next(request)


app.add_middleware(AuthGuardMiddleware)


def require_sensor_key(x_sensor_id: str = Header(...), x_sensor_key: str = Header(...)) -> str:
    expected = settings.SENSOR_KEYS.get(x_sensor_id)
    if not expected or expected != x_sensor_key:
        raise HTTPException(status_code=401, detail="Invalid sensor credentials")
    return x_sensor_id


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.get("/login")
async def login_page(request: Request):
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if token and decode_session_token(token):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "index.html", {"view": "login"})


@app.get("/")
async def dashboard_page(request: Request):
    # AuthGuardMiddleware already guarantees request.state.username is set here.
    return templates.TemplateResponse(request, "index.html", {"view": "dashboard"})


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------
class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login")
async def login(body: LoginBody, response: Response):
    valid = body.username == settings.ADMIN_USERNAME and verify_password(body.password, _ADMIN_HASH)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_session_token(body.username)
    resp = JSONResponse({"ok": True, "redirect": "/"})
    resp.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )
    return resp


@app.post("/api/v1/auth/logout")
async def logout():
    resp = JSONResponse({"ok": True, "redirect": "/login"})
    resp.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    return resp


# ---------------------------------------------------------------------------
# Dashboard-facing API (requires user session, enforced by the middleware)
# ---------------------------------------------------------------------------
@app.get("/api/v1/sensors")
async def list_sensors():
    return store.list_sensors()


@app.get("/api/v1/sensors/{sensor_id}/flows")
async def get_sensor_flows(sensor_id: str):
    flows = store.get_flows(sensor_id)
    if flows is None:
        raise HTTPException(status_code=404, detail="Unknown sensor")
    return {"sensor_id": sensor_id, "flows": flows}


@app.get("/api/v1/sensors/{sensor_id}/devices")
async def get_sensor_devices(sensor_id: str):
    devices = store.get_devices(sensor_id)
    if devices is None:
        raise HTTPException(status_code=404, detail="Unknown sensor")
    return {"sensor_id": sensor_id, "devices": devices}


# ---------------------------------------------------------------------------
# Sensor ingest API (sensor-key auth, not user session)
# ---------------------------------------------------------------------------
class FlowRecord(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    packets: int = 0
    bytes: int = 0
    first_seen: float
    last_seen: float


class FlowIngestBody(BaseModel):
    flows: list[FlowRecord]


@app.post("/api/v1/ingest/flows")
async def ingest_flows(body: FlowIngestBody, sensor_id: str = Depends(require_sensor_key)):
    store.ingest_flows(sensor_id, [f.model_dump() for f in body.flows])
    return {"ok": True, "received": len(body.flows)}


class DeviceRecord(BaseModel):
    ip: str
    mac: str
    vendor: str | None = "Unknown"


class DeviceIngestBody(BaseModel):
    devices: list[DeviceRecord]


@app.post("/api/v1/ingest/devices")
async def ingest_devices(body: DeviceIngestBody, sensor_id: str = Depends(require_sensor_key)):
    store.ingest_devices(sensor_id, [d.model_dump() for d in body.devices])
    return {"ok": True, "received": len(body.devices)}


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}
