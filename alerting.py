import os
import requests
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# In-memory alert cache for deduplication during continuous monitoring
_sent_alerts_cache = set()


def should_send_alert(module, target_id, signature):
    """
    Checks if an alert for (module, target_id, signature) has already been sent.
    Prevents repeated spam of identical findings during continuous monitoring,
    while ensuring M4 and M5 do not suppress each other.
    """
    key = f"{module}:{target_id}:{signature}"
    if key in _sent_alerts_cache:
        return False
    _sent_alerts_cache.add(key)
    return True


def clear_alert_cache():
    """Resets the alert deduplication cache."""
    _sent_alerts_cache.clear()


def send_telegram_alert(message):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if token is None:
        token = TELEGRAM_BOT_TOKEN
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if chat_id is None:
        chat_id = TELEGRAM_CHAT_ID

    if not token or not str(token).strip():
        return {
            "success": False,
            "error": "Telegram bot token not configured"
        }

    if not chat_id or not str(chat_id).strip():
        return {
            "success": False,
            "error": "Telegram chat ID not configured"
        }

    url = (
        f"https://api.telegram.org/bot"
        f"{token}/sendMessage"
    )

    data = {
        "chat_id": chat_id,
        "text": message
    }

    try:
        response = requests.post(
            url,
            data=data,
            timeout=10
        )

        result = response.json()

        if response.ok and result.get("ok"):
            return {
                "success": True,
                "message": "Telegram alert sent successfully"
            }

        return {
            "success": False,
            "error": result
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def dispatch_module_alert(module, message, target_id=None, signature=None):
    """
    Dispatches notifications to Telegram and Email independently.
    Ensures a failure or missing configuration in one channel never suppresses the other.
    Optionally deduplicates based on (module, target_id, signature).
    """
    if target_id and signature:
        if not should_send_alert(module, target_id, signature):
            return {
                "skipped": True,
                "reason": "Duplicate alert suppressed by deduplication policy",
                "telegram": {"success": False, "skipped": True},
                "email": {"success": False, "skipped": True}
            }

    telegram_res = {"success": False, "error": "Not attempted"}
    email_res = {"success": False, "error": "Not attempted"}

    # Isolated Telegram attempt
    try:
        telegram_res = send_telegram_alert(message)
    except Exception as te:
        telegram_res = {"success": False, "error": str(te)}

    # Isolated Email attempt
    try:
        from email_alerting import send_email_alert
        email_res = send_email_alert(message)
    except Exception as ee:
        email_res = {"success": False, "error": str(ee)}

    return {
        "skipped": False,
        "telegram": telegram_res,
        "email": email_res
    }


if __name__ == "__main__":

    result = send_telegram_alert(
        "🚨 KubeGuard M6 TEST ALERT\n\n"
        "This is a test security alert from KubeGuard."
    )

    print(result)
