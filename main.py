import threading
from core.packet_capture import start_sniffing
from utils.config import load_config
from core.logger import log_alert

# Optional: initialize ML model
try:
    from ml.model_predictor import load_model
    ml_model = load_model()
except ImportError:
    ml_model = None

def handle_packet(packet):
    from core.analyzer import extract_features
    from core.rules_engine import check_signatures
    from core.anomaly_detector import detect_anomaly
    from core.protocol_tracker import track_protocol

    features = extract_features(packet)
    if check_signatures(packet):
        log_alert("Signature-based threat detected.")
    elif detect_anomaly(features, model=ml_model):
        log_alert("Anomaly detected.")
    elif track_protocol(packet):
        log_alert("Protocol violation detected.")

def main():
    config = load_config()
    print("[IDS] Starting packet capture...")
    sniff_thread = threading.Thread(target=start_sniffing, args=(handle_packet,))
    sniff_thread.start()

if __name__ == "__main__":
    main()
