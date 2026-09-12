import os
import sys
import json
import asyncio
import threading

from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager


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

                "src_port": (
                    src_port
                    if src_port is not None
                    else "-"
                ),

                "dst_port": (
                    dst_port
                    if dst_port is not None
                    else "-"
                ),

                "protocol": protocol_name,

                "packet_count": data["packet_count"],

                "total_bytes": data["total_bytes"]
            })


    # Highest traffic first
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

        json_payload = json.dumps(
            snapshot_data
        )


        dead_connections = []


        for ws in active_connections:

            try:

                await ws.send_text(
                    json_payload
                )

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

    # Start packet sensor
    sensor_thread = threading.Thread(
        target=start_sensor_engine,
        daemon=True
    )

    sensor_thread.start()


    # Start WebSocket broadcaster
    asyncio.create_task(
        broadcast_loop()
    )


    yield


# ----------------------------------------------------------------------
# FASTAPI APPLICATION
# ----------------------------------------------------------------------

app = FastAPI(
    lifespan=lifespan
)


# ----------------------------------------------------------------------
# FRONTEND
# ----------------------------------------------------------------------

BACKEND_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

HTML_PATH = os.path.join(
    os.path.dirname(BACKEND_DIR),
    "frontend",
    "index.html"
)


@app.get("/")
async def serve_dashboard():

    return FileResponse(
        HTML_PATH
    )


# ----------------------------------------------------------------------
# WEBSOCKET
# ----------------------------------------------------------------------

@app.websocket("/ws/traffic")
async def traffic_websocket_endpoint(
    websocket: WebSocket
):

    await websocket.accept()

    active_connections.append(
        websocket
    )


    try:

        while True:

            await websocket.receive_text()


    except Exception:

        pass


    finally:

        if websocket in active_connections:

            active_connections.remove(
                websocket
            )


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