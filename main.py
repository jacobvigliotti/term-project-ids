from core.packet_sniffer import start_sniffing_thread
from core.packet_analyzer import get_stats
from core.packet_handler import handle_packet
from utils.config import load_config
from test.traffic_generator import TrafficGenerator


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
    TrafficGenerator.run_from_json("test/traffic_configs.json")
    
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