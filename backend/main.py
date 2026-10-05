"""
FastAPI Backend Entry Point (backend.main:app)
==============================================
Re-exports and launches the FastAPI app from backend.app.main when executed:
  python backend/main.py
"""

import os
import sys
import types

_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
if _ROOT_PATH not in sys.path:
    sys.path.insert(0, _ROOT_PATH)

# In Vercel Services where service root is 'backend/', 'backend' package is not in sys.path.
# Alias 'backend' and 'backend.app' to './app' specifically when 'backend' module is missing.
try:
    import backend.app
except ModuleNotFoundError as err:
    if err.name in ("backend", "backend.app"):
        import app
        _backend_mod = types.ModuleType("backend")
        _backend_mod.app = app
        sys.modules["backend"] = _backend_mod
        sys.modules["backend.app"] = app
    else:
        raise

from backend.app.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000)


