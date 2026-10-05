# ECDAT / Semicolon Backend API

FastAPI-powered Cryptographic Bill of Materials (CBOM) & Post-Quantum Cryptography (PQC) Readiness Engine with JWT user authentication, persistent scan history, and strict user isolation.

## Architecture

- **FastAPI Core**: REST endpoints under `/api/v1` and `/api`.
- **Database System**: SQLAlchemy relational engine (SQLite / PostgreSQL) with optional MongoDB document store synchronization.
- **Authentication**: JWT access tokens (24-hour expiration) with PBKDF2 password hashing.
- **Security**: Zip Slip path traversal defense, file upload boundary validation (`MAX_UPLOAD_SIZE_MB`), strict user isolation (HTTP 404 for unowned scans).

## API Endpoints

### Authentication
- `POST /api/auth/register`: Register new user account.
- `POST /api/auth/login`: Authenticate credentials & issue JWT token.
- `GET /api/auth/me`: Get current authenticated user profile.
- `POST /api/auth/forgot-password`: Request a 15-minute single-use password reset email via SMTP.
- `POST /api/auth/reset-password`: Reset account password using valid reset token.

### Scans & Inventory
- `POST /api/scans/upload`: Upload ZIP archive or target file (Zip Slip protected).
- `POST /api/scans`: Create scan job.
- `GET /api/scans`: List scans for authenticated user.
- `GET /api/scans/{id}/status`: Poll scan status & progress.
- `GET /api/scans/{id}/findings`: Fetch cryptographic inventory.
- `GET /api/scans/{id}/cbom`: Standardized CBOM JSON.
- `GET /api/scans/{id}/cyclonedx`: CycloneDX 1.6 document export.
- `GET /api/scans/{id}/risk`: Overall risk assessment.
- `GET /api/scans/{id}/mosca`: Mosca Theorem calculation.
- `GET /api/scans/{id}/migration`: MTech migration effort metrics.
- `GET /api/scans/{id}/remediation`: PQC patch recommendations & status tracking.
- `POST /api/scans/{id}/remediation/{finding_id}/status`: Update remediation state.
- `GET /api/scans/{id}/compliance`: Framework compliance report.
- `GET /api/scans/{id}/reminders`: Active scan reminders for critical & high risk findings.
- `DELETE /api/scans/{id}`: Delete scan record & disk artifacts.

## SMTP Email Setup (Password Reset)

To enable real email delivery for password resets:

1. Create a **Gmail App Password** (Google Account -> Security -> 2-Step Verification -> App Passwords).
2. Configure environment variables in `.env`:
   ```env
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your_email@gmail.com
   SMTP_PASSWORD=your_16_char_app_password
   SMTP_FROM=your_email@gmail.com
   FRONTEND_BASE_URL=http://localhost:8000
   PASSWORD_RESET_EXPIRE_MINUTES=15
   ```
3. Test delivery by triggering a password reset request from the UI or calling `POST /api/auth/forgot-password`.

## Running Tests

```bash
# Run auth, persistence, user isolation, password reset & zip security tests
python -m pytest backend/app/tests/test_auth_and_user_isolation.py backend/app/tests/test_password_reset.py -v

# Run full core scanner test suite
python -m pytest ECDAT-main/tests -v
```
