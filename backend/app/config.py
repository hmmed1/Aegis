"""Central configuration loaded from environment variables and the .env file."""

import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Auth ---
    dash_username: str
    dash_password_hash: str

    # --- JWT ---
    jwt_secret: str
    jwt_expire_minutes: int = 60

    # --- Server ---
    server_host: str = "127.0.0.1"
    server_port: int = 8000

    # --- Logging ---
    log_level: str = "INFO"
    log_format: str = "text"

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


# A single shared instance the whole app imports.
settings = Settings()