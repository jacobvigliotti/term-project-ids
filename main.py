from core.packet_analyzer import get_stats
from core.packet_sniffer import PacketSniffer
from utils.config import load_config
from test.traffic_generator import TrafficGenerator

sniffer_config = load_config("config.json")
generator_config = "test/traffic_config.json"

def print_stats():
    """Print current filtering statistics."""
    s = get_stats()
    print(f"\n--- Statistics ---")
    print(f"Allowed: {s['allowed']}")
    print(f"Blocked: {s['blocked']}")
    print(f"------------------\n")

def main():
    print("[IDS] Shallow Packet Inspection starting...")
    print(f"[IDS] Monitoring interface: {sniffer_config.get('interface', 'default')}")
    print(f"[IDS] Packet filter: {sniffer_config.get('packet_filter', 'ip')}")
    print(f"[IDS] Loaded {len(sniffer_config.get('filtering_rules', []))} filtering rules")
    print("[IDS] Press Ctrl+C to stop and see statistics\n")



    
    # Start capturing packets in background
    sniffer = PacketSniffer(sniffer_config)
    sniffer.start()
    traffic = TrafficGenerator(generator_config)
    traffic.start()
    traffic.join()
    sniffer.join()
    
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