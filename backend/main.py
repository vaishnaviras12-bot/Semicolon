import os
import sys

# Support both:
# 1. Running locally from the repository root:
#       python backend/main.py
# 2. Running with backend/ as the service root on Render:
#       uvicorn app.main:app

try:
    from backend.app.main import app
except ModuleNotFoundError as exc:
    if exc.name != "backend":
        raise

    backend_dir = os.path.dirname(os.path.abspath(__file__))

    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from app.main import app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )