import json
import time
import threading
from scapy.all import IP, TCP, UDP, send

class TrafficGenerator(threading.Thread):
    def __init__(self, config_path: str):
        super().__init__()  # initialize Thread base class

        # Load JSON config
        with open(config_path, "r") as f:
            config = json.load(f)

        # Core connection parameters
        self.src_ip = config.get("src_ip", "127.0.0.1")
        self.src_port = config.get("src_port", 12345)
        self.src_iface = config.get("src_iface", None)
        self.dst_ip = config.get("dst_ip", "127.0.0.1")
        self.dst_port = config.get("dst_port", 80)

        # List of traffic payload definitions
        self.traffic_payloads = config.get("traffic_payloads", [])

    def build_packet(self, protocol: str, payload: str):
        ip_layer = IP(src=self.src_ip, dst=self.dst_ip)

        if protocol.upper() == "TCP":
            transport_layer = TCP(sport=self.src_port, dport=self.dst_port)
        elif protocol.upper() == "UDP":
            transport_layer = UDP(sport=self.src_port, dport=self.dst_port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

        return ip_layer / transport_layer / payload

    def run(self):
        """Thread entry point: send traffic according to config"""
        for traffic in self.traffic_payloads:
            protocol = traffic.get("protocol", "TCP")
            payload = traffic.get("payload", "")
            interval = traffic.get("interval", 1.0)
            count = traffic.get("count", 1)

            for i in range(count):
                pkt = self.build_packet(protocol, payload)
                send(pkt, iface=self.src_iface, verbose=False)
                print(f"[{self.name}] Sent {protocol} packet {i+1}/{count} "
                      f"from {self.src_ip}:{self.src_port} "
                      f"to {self.dst_ip}:{self.dst_port} "
                      f"payload: {payload}")
                time.sleep(interval)


