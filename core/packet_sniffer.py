from scapy.all import sniff
import threading
from utils.pcap import save_pcap
from core.packet_handler import handle_packet

class PacketSniffer(threading.Thread):
    def __init__(self, config):
        """
        Initialize PacketSniffer as a thread.
        Loads configuration and sets up sniffing parameters.
        """
        super().__init__()
        self.config = config
        self.callback = handle_packet
        self.running = True

    def run(self):
        """
        Thread entry point: start sniffing packets.
        """
        iface = self.config["interface"]
        packet_filter = self.config["packet_filter"]
        capture_limit = self.config["capture_limit"]
        capture_timeout = self.config["capture_timeout"]

        print(f"[Sniffer] Starting sniffing on interface: {iface} with filter: '{packet_filter}'")

        packets = sniff(
            iface=iface,
            filter=packet_filter,
            prn=self.callback,
            store=True,
            count=capture_limit,
            timeout=capture_timeout
        )

        if len(packets) > 0:
            save_pcap(packets)
            print("[Sniffer] Finished sniff. Saved pcap.")
        else:
            print("[Sniffer] No packets to save.")

    def stop(self):
        """
        Stop the sniffer gracefully.
        """
        self.running = False
        # Note: Scapy's sniff() does not natively support external stop signals.
        # You can add a stop_filter=lambda pkt: not self.running to integrate this.

