"""
User Authentication API Endpoints
=================================
Provides endpoints for user registration, user login with JWT issuance,
current user profile retrieval, and OTP-based password reset (email + 6-digit code).
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database.connection import get_db, mongo_db
from backend.app.models.scan import UserModel, PasswordResetTokenModel
from backend.app.schemas.auth import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    ForgotPasswordRequest, ResetPasswordRequest, MessageResponse
)
from backend.app.utils.auth import (
    hash_password, verify_password, create_access_token, get_current_user
)
from backend.app.utils.email import send_password_reset_otp_email

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    """Register a new user account and issue a JWT access token."""
    email_clean = str(payload.email).lower().strip()
    
    # Check if user already exists
    existing_user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered."
        )
    
    # Create new user record
    pwd_hash = hash_password(payload.password)
    user_db = UserModel(
        name=payload.name.strip(),
        email=email_clean,
        password_hash=pwd_hash,
        created_at=datetime.utcnow()
    )
    db.add(user_db)
    db.commit()
    db.refresh(user_db)

    # Sync to MongoDB document store if connected
    if mongo_db is not None:
        try:
            mongo_db["users"].update_one(
                {"id": user_db.id},
                {"$set": {
                    "id": user_db.id,
                    "name": user_db.name,
                    "email": user_db.email,
                    "created_at": user_db.created_at
                }},
                upsert=True
            )
        except Exception:
            pass

    access_token = create_access_token(user_id=user_db.id, email=user_db.email)
    user_resp = UserResponse.model_validate(user_db)
    return TokenResponse(access_token=access_token, user=user_resp)

@router.post("/login", response_model=TokenResponse)
def login_user(payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user credentials and issue a JWT access token."""
    email_clean = str(payload.email).lower().strip()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    access_token = create_access_token(user_id=user.id, email=user.email)
    user_resp = UserResponse.model_validate(user)
    return TokenResponse(access_token=access_token, user=user_resp)

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: UserModel = Depends(get_current_user)):
    """Retrieve current authenticated user profile."""
    return UserResponse.model_validate(current_user)

def _hash_otp(user_id: str, otp: str) -> str:
    """
    Keyed hash of the OTP.  A bare SHA-256 of a 6-digit number could be reversed
    instantly (only 1,000,000 possibilities); mixing in the server secret and the
    user id makes a leaked database row useless on its own.
    """
    key = settings.JWT_SECRET.encode("utf-8")
    return hmac.new(key, f"{user_id}:{otp}".encode("utf-8"), hashlib.sha256).hexdigest()


GENERIC_FORGOT_MSG = (
    "If an account exists for this email, we've sent a 6-digit code to it. "
    "Please check your inbox and spam folder."
)


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Generates a 6-digit single-use OTP, stores only its keyed hash, and emails it to the
    account's registered address.  Always answers with the same message so attackers cannot
    discover which emails are registered.
    """
    email_clean = str(payload.email).lower().strip()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()

    if not user:
        return MessageResponse(message=GENERIC_FORGOT_MSG)

    now = datetime.utcnow()

    # Resend cooldown: stops someone from spamming a victim's inbox / burning SMTP quota.
    latest = (
        db.query(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.user_id == user.id)
        .order_by(PasswordResetTokenModel.created_at.desc())
        .first()
    )
    if latest and latest.used_at is None and latest.created_at and \
            (now - latest.created_at).total_seconds() < settings.PASSWORD_RESET_RESEND_COOLDOWN_SECONDS:
        return MessageResponse(message=GENERIC_FORGOT_MSG)

    # Invalidate every older unused code so only the newest one works.
    db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.used_at.is_(None),
    ).update({PasswordResetTokenModel.used_at: now}, synchronize_session=False)

    # secrets (CSPRNG), NOT random: 000000-999999 with leading zeros preserved.
    otp = f"{secrets.randbelow(1_000_000):06d}"
    reset_record = PasswordResetTokenModel(
        user_id=user.id,
        token_hash=_hash_otp(user.id, otp),
        expires_at=now + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        attempts=0,
        created_at=now,
    )
    db.add(reset_record)
    db.commit()

    try:
        send_password_reset_otp_email(user.email, otp)
    except ValueError as ve:
        db.delete(reset_record)
        db.commit()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(ve))
    except Exception:
        db.delete(reset_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="We couldn't send the code right now. Please try again later.",
        )

    return MessageResponse(message=GENERIC_FORGOT_MSG)


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Verifies email + 6-digit OTP and sets a new password.
    Max PASSWORD_RESET_MAX_ATTEMPTS wrong guesses per code, then the code is dead.
    """
    invalid = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired code.",
    )
    email_clean = str(payload.email).lower().strip()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise invalid  # same error as a wrong code: no account enumeration

    record = (
        db.query(PasswordResetTokenModel)
        .filter(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.used_at.is_(None),
        )
        .order_by(PasswordResetTokenModel.created_at.desc())
        .first()
    )
    now = datetime.utcnow()
    if not record or record.expires_at < now or record.attempts >= settings.PASSWORD_RESET_MAX_ATTEMPTS:
        raise invalid

    if not hmac.compare_digest(record.token_hash, _hash_otp(user.id, payload.otp)):
        record.attempts += 1
        if record.attempts >= settings.PASSWORD_RESET_MAX_ATTEMPTS:
            record.used_at = now  # burn the code; user must request a new one
        db.commit()
        raise invalid

    new_hash = hash_password(payload.new_password)
    user.password_hash = new_hash
    record.used_at = now
    db.commit()

    if mongo_db is not None:
        try:
            mongo_db["users"].update_one({"id": user.id}, {"$set": {"password_hash": new_hash}})
        except Exception:
            pass

    return MessageResponse(message="Password has been successfully reset. You can now log in with your new password.")
