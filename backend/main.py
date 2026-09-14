import os
import sys
import json
import asyncio
import threading

from pydantic import BaseModel
from fastapi import FastAPI, WebSocket, Response, Request, HTTPException, Depends
from fastapi.responses import FileResponse, RedirectResponse
from contextlib import asynccontextmanager
from fastapi.staticfiles import StaticFiles

# ----------------------------------------------------------------------
# IMPORT SENSOR
# ----------------------------------------------------------------------

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from sensors.capture import (
    active_flows,
    flows_lock,
    start_sensor_engine
)

# ----------------------------------------------------------------------
# WEBSOCKET CLIENTS
# ----------------------------------------------------------------------

active_connections = []

# ----------------------------------------------------------------------
# BUILD DASHBOARD SNAPSHOT
# ----------------------------------------------------------------------

def build_snapshot():
    with flows_lock:
        snapshot = []
        for key, data in active_flows.items():
            (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol_name
            ) = key

            snapshot.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port if src_port is not None else "-",
                "dst_port": dst_port if dst_port is not None else "-",
                "protocol": protocol_name,
                "packet_count": data["packet_count"],
                "total_bytes": data["total_bytes"]
            })

    snapshot.sort(
        key=lambda flow: flow["total_bytes"],
        reverse=True
    )
    return snapshot

# ----------------------------------------------------------------------
# WEBSOCKET BROADCAST
# ----------------------------------------------------------------------

async def broadcast_loop():
    while True:
        await asyncio.sleep(1.0)
        if not active_connections:
            continue

        snapshot_data = build_snapshot()
        json_payload = json.dumps(snapshot_data)
        dead_connections = []

        for ws in active_connections:
            try:
                await ws.send_text(json_payload)
            except Exception:
                dead_connections.append(ws)

        for dead in dead_connections:
            if dead in active_connections:
                active_connections.remove(dead)

# ----------------------------------------------------------------------
# FASTAPI LIFESPAN
# ----------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    sensor_thread = threading.Thread(
        target=start_sensor_engine,
        daemon=True
    )
    sensor_thread.start()
    asyncio.create_task(broadcast_loop())
    yield

# ----------------------------------------------------------------------
# FASTAPI APPLICATION
# ----------------------------------------------------------------------

app = FastAPI(lifespan=lifespan)

# ----------------------------------------------------------------------
# FRONTEND CONFIGURATION
# ----------------------------------------------------------------------

BACKEND_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

LOGIN_HTML_PATH = os.path.join(os.path.dirname(BACKEND_DIR), "frontend", "login.html")
DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(BACKEND_DIR), "frontend", "index.html")
ASSETS_DIR = os.path.join(os.path.dirname(BACKEND_DIR), "frontend", "assets")

app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")




# ----------------------------------------------------------------------
# Routing&Cookies Verification Automation
# ----------------------------------------------------------------------



async def verify_session_cookie(request: Request):
    session_cookie = request.cookies.get("session")
    if session_cookie != "authenticated" or session_cookie is None:
        raise HTTPException(status_code=303, detail="Redirecting...") 



# ----------------------------------------------------------------------
# ROUTING CONTROLLERS
# ----------------------------------------------------------------------
async def is_authenticated(request: Request) -> bool:
    session_cookie = request.cookies.get("session")
    return session_cookie == "authenticated" and session_cookie is not None



@app.get("/")
async def serve_default(request: Request, authenticated: bool = Depends(is_authenticated)):
    if authenticated:
        return FileResponse(DASHBOARD_HTML_PATH)
    return FileResponse(LOGIN_HTML_PATH)

@app.get("/dashboard")
async def serve_dashboard(authenticated: bool = Depends(is_authenticated)):
    if authenticated:
        return FileResponse(DASHBOARD_HTML_PATH)
    return RedirectResponse(url="/", status_code=303)





# ----------------------------------------------------------------------
# WEBSOCKET ENDPOINT
# ----------------------------------------------------------------------

@app.websocket("/ws/traffic")
async def traffic_websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)

# ----------------------------------------------------------------------
# AUTHENTICATION DATA MODELS
# ----------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str

# ----------------------------------------------------------------------
# CACHE CONTROL MIDDLEWARE
# ----------------------------------------------------------------------
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Target EVERY primary HTML routing endpoint aggressively
    if request.url.path in ["/", "/dashboard", "/login"]:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
    return response


# ----------------------------------------------------------------------
# AUTHENTICATION ENDPOINTS
# ----------------------------------------------------------------------
@app.get("/login")
async def serve_login_page(authenticated: bool = Depends(is_authenticated)):
    if authenticated:
        return RedirectResponse(url="/dashboard", status_code=303)
        
    return FileResponse(LOGIN_HTML_PATH)


@app.post("/login")
async def login(request: LoginRequest, response: Response):
    if request.username == "hmedd1" and request.password == "hmedd1":
        response.set_cookie(key="session", value="authenticated", httponly=True) 
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="session", httponly=True)
    return {"message": "Logged out successfully"}


# ----------------------------------------------------------------------
# DEVELOPMENT SERVER
# ----------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000
    )
