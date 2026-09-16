"""Filesystem paths shared across the app."""

import os

APP_DIR      = os.path.dirname(os.path.abspath(__file__))   # backend/app
BACKEND_DIR  = os.path.dirname(APP_DIR)                     # backend
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)                 # project root

FRONTEND_DIR        = os.path.join(PROJECT_ROOT, "frontend")
LOGIN_HTML_PATH     = os.path.join(FRONTEND_DIR, "login.html")
DASHBOARD_HTML_PATH = os.path.join(FRONTEND_DIR, "index.html")
ASSETS_DIR          = os.path.join(FRONTEND_DIR, "assets")