"""
Central configuration for the Aegis server, loaded entirely from environment
variables (see .env.example). Nothing here is hardcoded for production use.
"""
import os
import secrets


def _parse_sensor_keys(raw: str) -> dict[str, str]:
    """
    Parses SENSOR_KEYS="home-pc:supersecret1,office:supersecret2"
    into {"home-pc": "supersecret1", "office": "supersecret2"}.
    """
    pairs: dict[str, str] = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        sensor_id, key = chunk.split(":", 1)
        pairs[sensor_id.strip()] = key.strip()
    return pairs


class Settings:
    # --- Auth / session ---
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    # If ADMIN_PASSWORD isn't supplied, generate a random one and print it once
    # at startup rather than falling back to a known default credential.
    ADMIN_PASSWORD: str | None = os.getenv("ADMIN_PASSWORD")
    JWT_SECRET: str = os.getenv("JWT_SECRET", secrets.token_urlsafe(48))
    JWT_ALGORITHM: str = "HS256"
    SESSION_COOKIE_NAME: str = "aegis_session"
    SESSION_TTL_SECONDS: int = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12h

    # --- Sensors ---
    SENSOR_KEYS: dict[str, str] = _parse_sensor_keys(os.getenv("SENSOR_KEYS", ""))
    SENSOR_OFFLINE_TIMEOUT_SECONDS: int = 10

    # --- Misc ---
    ENV: str = os.getenv("ENV", "production")
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "true").lower() == "true"


settings = Settings()
