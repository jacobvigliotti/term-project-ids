import threading
from core.packet_capture import start_sniffing_thread
from utils.config import load_config
from utils.logger import log_alert


def handle_packet(packet):
    print(packet.show(dump=True))

    ''' 
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
    '''
        

def main():
    config = load_config()
    print("[IDS] Starting packet capture...")
    start_sniffing_thread(handle_packet)
    while True:
        pass

if __name__ == "__main__":
    main()
