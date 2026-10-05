"""
FastAPI Backend Entry Point (backend.main:app)
==============================================
Re-exports and launches the FastAPI app from backend.app.main when executed:
  python backend/main.py
"""

import os
import sys

_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
if _ROOT_PATH not in sys.path:
    sys.path.insert(0, _ROOT_PATH)

from backend.app.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000)

