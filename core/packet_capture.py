from scapy.all import sniff
import threading
from utils.config import load_config
from utils.pcap import save_pcap

# Optional: add filters or interface selection
config = load_config()
DEFAULT_FILTER = config["packet_filter"]
DEFAULT_INTERFACE = config["interface"]
DEFAULT_COUNT = config["capture_limit"]
DEFAULT_TIMEOUT = config["capture_timeout"]

def start_sniffing(callback, iface=DEFAULT_INTERFACE, packet_filter=DEFAULT_FILTER):
    """
    Starts packet sniffing using Scapy and sends each packet to the callback.
    
    Args:
        callback (function): Function to process each packet.
        iface (str): Network interface to sniff on (None = default).
        packet_filter (str): BPF filter string (e.g., "tcp", "udp", "port 80").
    """
    print(f"[Sniffer] Starting sniffing on interface: {iface or 'default'} with filter: '{packet_filter}'")
    packet = sniff(
        iface=iface,
        filter=packet_filter,
        prn=callback,
        store=False,
        count = DEFAULT_COUNT,
        timeout =  DEFAULT_TIMEOUT
    )
    save_pcap(packet)

def start_sniffing_thread(callback, iface=DEFAULT_INTERFACE, packet_filter=DEFAULT_FILTER):
    """
    Starts sniffing in a separate thread.
    """
    thread = threading.Thread(target=start_sniffing, args=(callback, iface, packet_filter))
    thread.daemon = True
    thread.start()
    print("[Sniffer] Sniffing thread started.")
