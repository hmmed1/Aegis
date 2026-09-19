"""Shared pytest fixtures for the Aegis test suite."""

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

os.environ["ENV_FILE"] = str(BACKEND_DIR / ".env.test")

import pytest
from app.main import app as fastapi_app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """A fresh TestClient per test — no state leaks between tests."""
    with TestClient(fastapi_app) as c:
        yield c