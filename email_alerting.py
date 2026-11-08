import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv


load_dotenv()


def send_email_alert(message):
    if os.getenv("ALERT_EMAIL_ENABLED", "true").lower() == "false":
        return {
            "success": False,
            "error": "Email alerting disabled"
        }

    receiver = os.getenv("EMAIL_RECEIVER") or os.getenv("ALERT_EMAIL_RECEIVER") or os.getenv("ALERT_EMAIL_TO")
    sender = os.getenv("EMAIL_SENDER") or os.getenv("ALERT_EMAIL_SENDER") or os.getenv("ALERT_EMAIL_FROM") or "kubeguard@security.internal"
    password = os.getenv("EMAIL_APP_PASSWORD") or os.getenv("SMTP_PASSWORD")
    server_host = os.getenv("SMTP_SERVER", "smtp.gmail.com")

    if not receiver:
        return {
            "success": False,
            "error": "Email configuration missing"
        }

    # If using Gmail default without credentials
    if server_host == "smtp.gmail.com" and (not sender or not password):
        return {
            "success": False,
            "error": "Email configuration missing"
        }

    try:
        email = MIMEText(message)
        email["Subject"] = "KubeGuard Security Alert"
        email["From"] = sender
        email["To"] = receiver

        port = int(os.getenv("SMTP_PORT", 465 if server_host == "smtp.gmail.com" else 587))
        if server_host == "smtp.gmail.com" or port == 465:
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP

        with smtp_cls(server_host, port, timeout=10) as server:
            if password:
                server.login(sender, password)
            server.sendmail(sender, receiver, email.as_string())

        return {
            "success": True,
            "message": "Email alert sent successfully"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
