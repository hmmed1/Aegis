"""Authentication: password checks, JWT sessions, and auth routes."""

import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pwdlib import PasswordHash
from pydantic import BaseModel

from app.config import settings
from app.paths import LOGIN_HTML_PATH

logger = logging.getLogger(__name__)

password_hash = PasswordHash.recommended()
router = APIRouter()


# --- Request model ----------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


# --- Credential check -------------------------------------------------

def authenticate_user(username: str, password: str) -> bool:
    username_ok = username == settings.dash_username
    password_ok = password_hash.verify(password, settings.dash_password_hash)
    return username_ok and password_ok


# --- JWT helpers ------------------------------------------------------

def create_access_token(username: str) -> str:
    """Sign a JWT for the given username, valid for settings.jwt_expire_minutes."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,                                    
        "iat": int(now.timestamp()),                      
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> str | None:
    """Return the username from a valid token, or None if invalid/expired."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return payload.get("sub")


# --- Current-user dependency ------------------------------------------

async def get_current_user(request: Request) -> str | None:
    """Return the logged-in username, or None if not authenticated."""
    token = request.cookies.get("session")
    if not token:
        return None
    return decode_access_token(token)


# --- Routes -----------------------------------------------------------

@router.get("/login")
async def serve_login_page(user: str | None = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    return FileResponse(LOGIN_HTML_PATH)


@router.post("/login")
def login(request: LoginRequest, response: Response):
    if not authenticate_user(request.username, request.password):
        logger.warning("login failed user=%s", request.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(request.username)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.jwt_expire_minutes * 60,
    )
    logger.info("login succeeded user=%s", request.username)
    return {"message": "Login successful"}


@router.post("/logout")
async def logout(response: Response):
    logger.info("logout")
    response.delete_cookie(key="session", httponly=True)
    return {"message": "Logged out successfully"}