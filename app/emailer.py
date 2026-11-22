import os
import smtplib
from email.message import EmailMessage


def is_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST", "").strip())


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        raise RuntimeError("SMTP is not configured")
    port = int(os.environ.get("SMTP_PORT", "587").strip() or "587")
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", "").strip() or user or "no-reply@fareguard.local"
    mode = os.environ.get("SMTP_TLS", "starttls").strip().lower()

    message = EmailMessage()
    message["Subject"] = "Reset your FareGuard password"
    message["From"] = sender
    message["To"] = to_email
    message.set_content(
        "Use the link below to reset your FareGuard password. "
        "It expires in 30 minutes.\n\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can ignore this email.\n"
    )

    if mode == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
        return

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if mode == "starttls":
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(message)
