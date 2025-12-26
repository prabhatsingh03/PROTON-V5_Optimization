"""
Email service utilities for sending transactional messages via SMTP.

This module centralizes all email logic including template rendering,
retry handling, and audit logging to keep app.py uncluttered.
"""
import json
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional, Tuple

from config import (
    OTP_EXPIRY_MINUTES,
    RESET_TOKEN_EXPIRY_HOURS,
    SMTP_FROM_EMAIL,
    SMTP_FROM_NAME,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USERNAME,
)
from utils.db_utils import execute_primary_query

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(os.path.dirname(PROJECT_ROOT), "templates", "emails")

MAX_EMAIL_ATTEMPTS = 3
SMTP_TIMEOUT = 30  # seconds


def _is_smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD)


if _is_smtp_configured():
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        print("Email service initialized with SMTP credentials")
else:
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        print(
            "WARNING: SMTP credentials missing or incomplete. Email features (OTP, password reset) are disabled."
        )


def render_email_template(template_name: str, context: Optional[Dict[str, str]] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Render an HTML template from templates/emails with simple placeholder replacement.

    Returns tuple of (success flag, rendered_html, error_message).
    """
    context = context or {}
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    try:
        with open(template_path, "r", encoding="utf-8") as template_file:
            template_content = template_file.read()
    except FileNotFoundError:
        return False, None, f"Template {template_name} not found."
    except Exception as exc:
        return False, None, f"Error reading template {template_name}: {exc}"

    rendered = template_content
    for key, value in context.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", str(value or ""))
    # Replace any remaining placeholders with empty string
    while "{{" in rendered and "}}" in rendered:
        start = rendered.find("{{")
        end = rendered.find("}}", start)
        if end == -1:
            break
        rendered = rendered[:start] + "" + rendered[end + 2 :]

    return True, rendered, None


def log_email_audit(
    action: str,
    to_email: str,
    subject: str,
    email_type: str,
    error: Optional[str] = None,
    *,
    org_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> None:
    """
    Insert an audit log entry for email operations.
    """
    try:
        payload = {
            "to_email": to_email,
            "subject": subject,
            "email_type": email_type,
        }
        if error:
            payload["error"] = error
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, user_id, action, json.dumps(payload)),
            commit=True,
        )
    except Exception:
        # Audit logging must never block email flow
        pass


def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    email_type: str = "generic",
    org_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Send an email using configured SMTP credentials with retry logic.
    """
    if not _is_smtp_configured():
        warning = "SMTP configuration missing. Email not sent."
        log_email_audit("email_failed", to_email, subject, email_type, warning, org_id=org_id, user_id=user_id)
        return False, warning

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = to_email

    plain_text = text_body or "Please view this email in an HTML-compatible client."
    message.attach(MIMEText(plain_text, "plain"))
    message.attach(MIMEText(html_body, "html"))

    last_error = None
    for attempt in range(1, MAX_EMAIL_ATTEMPTS + 1):
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM_EMAIL, [to_email], message.as_string())
            log_email_audit("email_sent", to_email, subject, email_type, org_id=org_id, user_id=user_id)
            return True, None
        except smtplib.SMTPAuthenticationError as exc:
            last_error = f"SMTP authentication failed: {exc}"
        except smtplib.SMTPServerDisconnected as exc:
            last_error = f"SMTP server disconnected: {exc}"
        except smtplib.SMTPException as exc:
            last_error = f"SMTP error: {exc}"
        except Exception as exc:
            last_error = f"Unexpected error sending email: {exc}"

        log_email_audit("email_failed", to_email, subject, email_type, last_error, org_id=org_id, user_id=user_id)
        if attempt < MAX_EMAIL_ATTEMPTS:
            time.sleep(2 ** attempt)

    return False, last_error


def send_otp_email(
    to_email: str,
    otp_code: str,
    user_name: Optional[str] = None,
    *,
    org_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Send a login OTP email using the OTP template.
    """
    context = {
        "USER_NAME": user_name or "",
        "OTP_CODE": otp_code,
        "EXPIRY_MINUTES": OTP_EXPIRY_MINUTES,
    }
    success, html_body, error = render_email_template("otp_email.html", context)
    if not success or not html_body:
        log_email_audit(
            "email_failed",
            to_email,
            "Your PROTON Login OTP Code",
            "otp",
            error,
            org_id=org_id,
            user_id=user_id,
        )
        return False, error

    return send_email(
        to_email=to_email,
        subject="Your PROTON Login OTP Code",
        html_body=html_body,
        email_type="otp",
        org_id=org_id,
        user_id=user_id,
    )


def send_password_reset_email(
    to_email: str,
    reset_link: str,
    user_name: Optional[str] = None,
    *,
    org_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Send a password reset email using the reset template.
    """
    context = {
        "USER_NAME": user_name or "",
        "RESET_LINK": reset_link,
        "EXPIRY_HOURS": RESET_TOKEN_EXPIRY_HOURS,
    }
    success, html_body, error = render_email_template("password_reset_email.html", context)
    if not success or not html_body:
        log_email_audit(
            "email_failed",
            to_email,
            "Reset Your PROTON Password",
            "password_reset",
            error,
            org_id=org_id,
            user_id=user_id,
        )
        return False, error

    return send_email(
        to_email=to_email,
        subject="Reset Your PROTON Password",
        html_body=html_body,
        email_type="password_reset",
        org_id=org_id,
        user_id=user_id,
    )


__all__ = [
    "send_email",
    "send_otp_email",
    "send_password_reset_email",
    "render_email_template",
]

