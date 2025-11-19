import os
from datetime import datetime
from utils.config import load_config

# Load config once
config = load_config()
LOG_PATH = config.get("alert_log_path", "alerts.log")

def log_alert(message, source_ip=None, severity="INFO"):
    """
    Logs an alert to the configured log file with timestamp and optional metadata.

    Args:
        message (str): Description of the alert.
        source_ip (str): Optional source IP address.
        severity (str): Alert level (e.g., INFO, WARNING, CRITICAL).
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{severity}] {message}"
    if source_ip:
        log_entry += f" | Source IP: {source_ip}"

    try:
        with open(LOG_PATH, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"[Logger] Failed to write to log file: {e}")

    # Optional: print to console
    print(log_entry)
