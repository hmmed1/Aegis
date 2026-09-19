import os
import sys

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)
import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.auth import router as auth_router
from app.logging_config import setup_logging
from app.paths import ASSETS_DIR
from app.routes.pages import router as pages_router
from app.routes.websocket import broadcast_loop
from app.routes.websocket import router as ws_router
from sensors.capture import start_sensor_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting sensor thread")
    sensor_thread = threading.Thread(target=start_sensor_engine, daemon=True)
    sensor_thread.start()

    logger.info("starting websocket broadcast loop")
    asyncio.create_task(broadcast_loop())

    logger.info("app startup complete")
    yield
    logger.info("app shutting down")


app = FastAPI(lifespan=lifespan)
setup_logging()
logger = logging.getLogger(__name__)

app.include_router(auth_router)
app.include_router(pages_router)
app.include_router(ws_router)
app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path in ["/", "/dashboard", "/login"]:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000)