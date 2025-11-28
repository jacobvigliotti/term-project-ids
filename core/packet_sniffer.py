from scapy.all import sniff, get_if_list
import threading
from utils.config import load_config
from utils.pcap import save_pcap

# Optional: add filters or interface selection
config = load_config()

def start_sniffing(callback):
    """
    Starts packet sniffing using Scapy and sends each packet to the callback.
    """
    iface=config["interface"]
    filter=config["packet_filter"]
    print(f"[Sniffer] Starting sniffing on interface: {iface} with filter: '{filter}'")
    packet = sniff(
        iface=iface,
        filter=filter,
        prn=callback,
        store=True,
        count = config["capture_limit"],
        timeout =  config["capture_timeout"]
    )
    
    if(len(packet) > 0):
        save_pcap(packet)
        print("finished sniff. save pcap.")
    else:
        print("No packets to save.")

def start_sniffing_thread(callback):
    """
    Starts sniffing in a separate thread.
    """
    thread = threading.Thread(target=start_sniffing, args=(callback,))
    thread.daemon = True
    thread.start()
    print("[Sniffer] Sniffing thread started.")
