import os
import sys

# When running locally from the repository root:
#   backend.app.main
#
# When running as a Vercel service with backend/ as the service root:
#   app.main

try:
    from backend.app.main import app
except ModuleNotFoundError as exc:
    if exc.name != "backend":
        raise

    # Vercel's service root is the backend/ directory,
    # so the app package is directly importable as "app".
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