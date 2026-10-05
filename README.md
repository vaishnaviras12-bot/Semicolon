# ECDAT Cryptographic Bill of Materials (CBOM) & PQC Engine

Single-server FastAPI backend serving both `/api/...` endpoints and the production React SPA frontend.

## How to Run

### Single-Server Mode (Production / Unified Server)

> **IMPORTANT**: The application **MUST** be started from the project root directory because `DATABASE_URL` is configured to `sqlite:///./ecdat_pqc.db` (relative to the current working directory). Starting from another directory will cause a new/separate database file to be created.

1. **Build the Frontend**:
   ```bash
   npm run build
   ```
2. **Start the Unified Server**:
   ```bash
   npm start
   ```
   Or directly using Python:
   ```bash
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
   ```
3. Open your browser at:
   [http://localhost:8000](http://localhost:8000)

### Dual-Server Mode (Development)

To run Vite dev server alongside FastAPI uvicorn reloader:
```bash
npm run dev
```
- Frontend (Vite Dev Server): [http://localhost:5173](http://localhost:5173)
- Backend API (FastAPI): [http://localhost:8000](http://localhost:8000)

## Security Features

- **Path Traversal Protection**: Static file requests in SPA fallback catch-all routes verify canonical real paths (`os.path.realpath`) to prevent directory traversal outside `dist` (e.g. `GET /../../.env`).
- **Dotfile Shielding**: Hidden files and dotfiles (e.g., `.env`, `.git`) are strictly prohibited from being served as static assets.
- **Unmapped API Routes**: Requests starting with `/api` return a standard JSON 404 response (`{"detail": "API route not found"}`) rather than falling back to HTML.
- **Idempotent SQLite Schema Sync**: Database tables automatically migrate missing model columns without resetting or deleting existing records.
