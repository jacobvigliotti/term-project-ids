from core.packet_capture import start_sniffing_thread
from core.analyzer import extract_features
from core.rules_engine import check_packet, get_stats
from core.logger import log_alert
from utils.config import load_config

def handle_packet(packet):
    """
    Process each captured packet.
    Extract headers, check against rules, and log the result.
    """
    # Pull out the header info we care about
    features = extract_features(packet)
    
    # Skip packets without IP layer (like ARP)
    # We can't really filter these with IP-based rules
    if features["src_ip"] is None:
        return
    
    # Check this packet against our filtering rules
    action, reason = check_packet(features)
    
    # Build a message describing the packet
    if features["src_port"]:
        # TCP or UDP packet
        packet_info = (
            f"{features['protocol'].upper()} "
            f"{features['src_ip']}:{features['src_port']} -> "
            f"{features['dst_ip']}:{features['dst_port']}"
        )
    else:
        # ICMP or other protocol without ports
        packet_info = (
            f"{features['protocol'].upper()} "
            f"{features['src_ip']} -> {features['dst_ip']}"
        )
    
    # Log based on action
    if action == "block":
        severity = "WARNING"
        message = f"BLOCKED: {packet_info} | Reason: {reason}"
    else:
        severity = "INFO"
        message = f"ALLOWED: {packet_info} | Reason: {reason}"
    
    log_alert(message, source_ip=features["src_ip"], severity=severity)

def print_stats():
    """Print current filtering statistics."""
    s = get_stats()
    print(f"\n--- Statistics ---")
    print(f"Allowed: {s['allowed']}")
    print(f"Blocked: {s['blocked']}")
    print(f"------------------\n")

def main():
    config = load_config()
    
    print("[IDS] Shallow Packet Inspection starting...")
    print(f"[IDS] Monitoring interface: {config.get('interface', 'default')}")
    print(f"[IDS] Packet filter: {config.get('packet_filter', 'ip')}")
    print(f"[IDS] Loaded {len(config.get('filtering_rules', []))} filtering rules")
    print("[IDS] Press Ctrl+C to stop and see statistics\n")
    
    # Start capturing packets in background
    start_sniffing_thread(handle_packet)
    
    try:
        # Keep the program running
        while True:
            pass
    except KeyboardInterrupt:
        # User pressed Ctrl+C
        print("\n[IDS] Shutting down...")
        print_stats()

if __name__ == "__main__":
    main()