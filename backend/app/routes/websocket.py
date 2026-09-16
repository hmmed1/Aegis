
"""WebSocket endpoint that streams live traffic snapshots to clients."""

import asyncio
import json

from fastapi import APIRouter, WebSocket

from sensors.capture import active_flows, flows_lock
import logging

logger = logging.getLogger(__name__)



router = APIRouter()

# Connected WebSocket clients.
active_connections: list[WebSocket] = []


def build_snapshot() -> list[dict]:
    """Return the current flows as a sorted list of dicts (biggest first)."""
    with flows_lock:
        snapshot = []
        for key, data in active_flows.items():
            (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol_name,
            ) = key

            snapshot.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port if src_port is not None else "-",
                "dst_port": dst_port if dst_port is not None else "-",
                "protocol": protocol_name,
                "packet_count": data["packet_count"],
                "total_bytes": data["total_bytes"],
            })

    snapshot.sort(key=lambda flow: flow["total_bytes"], reverse=True)
    return snapshot


async def broadcast_loop() -> None:
    """Every second, push the current snapshot to every connected client."""
    while True:
        await asyncio.sleep(1.0)
        if not active_connections:
            continue

        payload = json.dumps(build_snapshot())
        dead: list[WebSocket] = []

        for ws in active_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            if ws in active_connections:
                active_connections.remove(ws)



@router.websocket("/ws/traffic")
async def traffic_websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    logger.info("websocket client connected (total=%d)", len(active_connections))
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
        logger.info("websocket client disconnected (total=%d)", len(active_connections))