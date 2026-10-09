"""
SendGrid HTTPS Email Delivery Utility
======================================
Delivers the 6-digit password-reset OTP using SendGrid's official HTTPS Mail Send API
(https://api.sendgrid.com/v3/mail/send) on port 443.

This HTTPS transport bypasses cloud host outbound TCP SMTP port blocks (ports 25, 465, 587)
such as those enforced on Render Free web services.

Configuration Environment Variables:
  - SENDGRID_API_KEY: SendGrid API key (e.g. SG.xxxx)
  - SENDGRID_FROM_EMAIL: Verified SendGrid sender address (e.g. support@yourdomain.com)
  - Fallback: Uses SMTP_PASSWORD (if SG. key) and SMTP_FROM for backward compatibility.
"""

import logging
import requests
from backend.app.config import settings

logger = logging.getLogger("ecdat.email")

SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"


def send_password_reset_otp_email(to_email: str, otp: str) -> None:
    """
    Email a 6-digit OTP to the account's registered address via SendGrid HTTPS Mail Send API.
    Raises ValueError if configuration is missing/invalid or HTTP delivery fails.
    """
    # 1. Resolve SendGrid API Key (explicit SENDGRID_API_KEY preferred; fallback to SG.* in SMTP_PASSWORD)
    api_key = settings.SENDGRID_API_KEY
    if not api_key and settings.SMTP_PASSWORD and settings.SMTP_PASSWORD.startswith("SG."):
        api_key = settings.SMTP_PASSWORD

    if not api_key:
        logger.warning("SendGrid API Key (SENDGRID_API_KEY) missing in environment. Unable to deliver OTP.")
        raise ValueError("SMTP delivery service is not configured on this server.")

    # 2. Resolve Verified Sender Address (SENDGRID_FROM_EMAIL preferred; fallback to SMTP_FROM)
    from_addr = settings.SENDGRID_FROM_EMAIL or settings.SMTP_FROM
    if not from_addr and settings.SMTP_USERNAME and "@" in settings.SMTP_USERNAME and settings.SMTP_USERNAME.strip().lower() != "apikey":
        from_addr = settings.SMTP_USERNAME

    if not from_addr or "@" not in from_addr or from_addr.strip().lower() == "apikey":
        logger.warning("SendGrid sender address (SENDGRID_FROM_EMAIL / SMTP_FROM) missing or invalid. Unable to deliver OTP.")
        raise ValueError("SMTP sender address (SMTP_FROM) is not configured correctly.")

    minutes = settings.PASSWORD_RESET_EXPIRE_MINUTES

    text_content = (
        f"Hello,\n\n"
        f"Use this one-time code to reset your Semicolon / ECDAT account password:\n\n"
        f"    {otp}\n\n"
        f"The code is valid for {minutes} minutes and can be used only once.\n"
        f"Never share this code with anyone.\n\n"
        f"If you did not request a password reset, ignore this email - your password will not change.\n\n"
        f"Semicolon - ECDAT Post-Quantum Cryptography Readiness Engine\n"
    )

    digits_html = "".join(
        f'<span style="display:inline-block;width:42px;height:52px;line-height:52px;margin:0 4px;'
        f'background:#0b0f17;border:1px solid #c9a227;border-radius:8px;font-size:26px;'
        f'font-weight:700;color:#f5d56b;text-align:center;font-family:monospace;">{d}</span>'
        for d in otp
    )

    html_content = (
        f'<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#0b0f17;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#cbd5e1;">'
        f'<div style="max-width:520px;margin:0 auto;background:#131b2e;border:1px solid #23314d;border-radius:12px;padding:32px;">'
        f'<div style="font-size:20px;font-weight:700;color:#f59e0b;margin-bottom:18px;">Semicolon &middot; ECDAT Platform</div>'
        f'<p style="font-size:14.5px;line-height:1.6;">A password reset was requested for <strong>{to_email}</strong>. Enter this code to continue:</p>'
        f'<div style="text-align:center;margin:26px 0;">{digits_html}</div>'
        f'<p style="font-size:13px;color:#fbbf24;">This code expires in <strong>{minutes} minutes</strong> and works only once. Never share it with anyone.</p>'
        f'<p style="font-size:12px;color:#64748b;border-top:1px solid #1e293b;padding-top:14px;margin-top:24px;">'
        f'If you did not request this, you can safely ignore this email. Your password will not change.</p>'
        f'</div></body></html>'
    )

    payload = {
        "personalizations": [
            {
                "to": [{"email": to_email}]
            }
        ],
        "from": {
            "email": from_addr,
            "name": "Semicolon ECDAT Platform"
        },
        "subject": f"{otp} is your Semicolon password reset code",
        "content": [
            {
                "type": "text/plain",
                "value": text_content
            },
            {
                "type": "text/html",
                "value": html_content
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(SENDGRID_API_URL, json=payload, headers=headers, timeout=15)

        if response.status_code in (200, 201, 202):
            logger.info("Password reset OTP email dispatched successfully via SendGrid HTTPS API.")
            return

        if response.status_code == 401:
            logger.error("SendGrid API authentication failed (HTTP 401). Invalid or revoked SENDGRID_API_KEY.")
            raise ValueError("SendGrid authentication failed. Please verify SENDGRID_API_KEY in server environment.")

        if response.status_code in (400, 403):
            logger.error(f"SendGrid API rejected request (HTTP {response.status_code}). Check sender verification.")
            raise ValueError("SendGrid delivery rejected. Please verify sender address (SENDGRID_FROM_EMAIL).")

        logger.error(f"Unexpected response from SendGrid API (HTTP {response.status_code}).")
        raise ValueError(f"SendGrid delivery failed with status code {response.status_code}.")

    except requests.exceptions.Timeout:
        logger.error("Timeout connecting to SendGrid HTTPS API (port 443).")
        raise ValueError("Timeout connecting to email delivery service.")
    except requests.exceptions.RequestException as e:
        logger.error(f"SendGrid HTTPS API connection error: {type(e).__name__}")
        raise ValueError("Failed to deliver email through SendGrid HTTPS API.")
