"""
SMTP Email Delivery Utility
===========================
Sends the 6-digit password-reset OTP through SendGrid SMTP (or any standard SMTP server)
using Python's standard smtplib.  STARTTLS on 587, implicit SSL on 465.

SendGrid setup: Set SMTP_HOST=smtp.sendgrid.net, SMTP_PORT=587,
SMTP_USERNAME=apikey, SMTP_PASSWORD=<SendGrid API key>, and
SMTP_FROM=<verified sender address>.
"""

import logging
import smtplib
from email.message import EmailMessage
from backend.app.config import settings

logger = logging.getLogger("ecdat.email")


def send_password_reset_otp_email(to_email: str, otp: str) -> None:
    """
    Email a 6-digit OTP to the account's registered address.
    Raises ValueError if SMTP credentials are missing, or an smtplib/OS error on delivery failure.
    """
    if not settings.SMTP_HOST or not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        logger.warning("SMTP credentials/host missing in environment. Unable to deliver OTP.")
        raise ValueError("SMTP delivery service is not configured on this server.")

    from_addr = settings.SMTP_FROM
    if not from_addr and settings.SMTP_USERNAME and "@" in settings.SMTP_USERNAME:
        from_addr = settings.SMTP_USERNAME

    if not from_addr or "@" not in from_addr or from_addr.strip().lower() == "apikey":
        logger.warning("SMTP sender address (SMTP_FROM) is missing or invalid. Unable to deliver OTP.")
        raise ValueError("SMTP sender address (SMTP_FROM) is not configured correctly.")
    minutes = settings.PASSWORD_RESET_EXPIRE_MINUTES

    msg = EmailMessage()
    msg["Subject"] = f"{otp} is your Semicolon password reset code"
    msg["From"] = from_addr
    msg["To"] = to_email

    msg.set_content(
        f"""Hello,

Use this one-time code to reset your Semicolon / ECDAT account password:

    {otp}

The code is valid for {minutes} minutes and can be used only once.
Never share this code with anyone.

If you did not request a password reset, ignore this email - your password will not change.

Semicolon - ECDAT Post-Quantum Cryptography Readiness Engine
"""
    )

    digits = "".join(
        f'<span style="display:inline-block;width:42px;height:52px;line-height:52px;margin:0 4px;'
        f'background:#0b0f17;border:1px solid #c9a227;border-radius:8px;font-size:26px;'
        f'font-weight:700;color:#f5d56b;text-align:center;font-family:monospace;">{d}</span>'
        for d in otp
    )
    msg.add_alternative(
        f"""<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#0b0f17;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#cbd5e1;">
  <div style="max-width:520px;margin:0 auto;background:#131b2e;border:1px solid #23314d;border-radius:12px;padding:32px;">
    <div style="font-size:20px;font-weight:700;color:#f59e0b;margin-bottom:18px;">Semicolon &middot; ECDAT Platform</div>
    <p style="font-size:14.5px;line-height:1.6;">A password reset was requested for <strong>{to_email}</strong>. Enter this code to continue:</p>
    <div style="text-align:center;margin:26px 0;">{digits}</div>
    <p style="font-size:13px;color:#fbbf24;">This code expires in <strong>{minutes} minutes</strong> and works only once. Never share it with anyone.</p>
    <p style="font-size:12px;color:#64748b;border-top:1px solid #1e293b;padding-top:14px;margin-top:24px;">
      If you did not request this, you can safely ignore this email. Your password will not change.</p>
  </div>
</body></html>""",
        subtype="html",
    )

    host, port = settings.SMTP_HOST, settings.SMTP_PORT
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
        logger.info("Password reset OTP dispatched.")
    except Exception as e:
        logger.error(f"Failed to send OTP email via SMTP ({host}:{port}): {e}")
        raise
