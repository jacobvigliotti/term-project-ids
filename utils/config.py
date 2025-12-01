import json
import os

# Default configuration values
DEFAULT_CONFIG = {
    "interface": None,               # None for auto
    "packet_filter": "tcp",             # BPF filter string (e.g., "tcp", "udp", "port 80")
    "syn_flood_threshold": 100,        # SYN packets per IP per minute
    "alert_log_path": "alerts.log",    # Where to store alerts
    "ml_model_path": "ml/models/ids_model.pkl",  # Path to trained ML model
    "enable_dashboard": False,         # Toggle Flask dashboard
    "capture_limit": 0,                # 0 = unlimited packets
    "capture_timeout": 120,              #2 minutes
    "log_raw_packets": False,          # Save raw packets to PCAP
    "pcap_output_path": "logs/capture.pcap"
}

CONFIG_PATH = "config.json"

def load_config(path=CONFIG_PATH):
    """
    Loads configuration from JSON file. Falls back to defaults if file is missing or invalid.
    """
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                user_config = json.load(f)
            print(f"[Config] Loaded config file: {path}")
            return {**DEFAULT_CONFIG, **user_config}
        except Exception as e:
            print(f"[Config] Failed to load config file: {e}")
    else:
        print("[Config] No config file found. Using defaults.")
    return DEFAULT_CONFIG
