import os
from datetime import datetime


LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")


def log_alert(module, severity, status, message):

    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    log_entry = (
        f"[{timestamp}] "
        f"MODULE={module} | "
        f"SEVERITY={severity} | "
        f"STATUS={status} | "
        f"{message}\n"
    )

    with open(LOG_FILE, "a") as file:

        file.write(log_entry)


def get_alert_log():

    if not os.path.exists(LOG_FILE):

        return []

    with open(LOG_FILE, "r") as file:

        return file.readlines()
