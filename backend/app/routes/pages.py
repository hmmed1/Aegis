"""HTML page routes: landing page and dashboard."""

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, RedirectResponse

from app.auth import get_current_user
from app.paths import DASHBOARD_HTML_PATH, LOGIN_HTML_PATH

router = APIRouter()


@router.get("/")
async def serve_default(user: str | None = Depends(get_current_user)):
    if user:
        return FileResponse(DASHBOARD_HTML_PATH)
    return FileResponse(LOGIN_HTML_PATH)


@router.get("/dashboard")
async def serve_dashboard(user: str | None = Depends(get_current_user)):
    if user:
        return FileResponse(DASHBOARD_HTML_PATH)
    return RedirectResponse(url="/", status_code=303)