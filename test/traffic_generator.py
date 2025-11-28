import threading
import time
import json
from scapy.all import IP, TCP, UDP, Raw, send

class TrafficGenerator(threading.Thread):
    def __init__(self, cfg: dict):
        """
        Initialize TrafficGenerator from a config dictionary.
        cfg should be a Python dict with keys:
        dst_ip, dst_port, protocol, payload, interval, count
        """
        super().__init__()
        self.dst_ip = cfg.get("dst_ip", "127.0.0.1")
        self.dst_port = cfg.get("dst_port", 80)
        self.protocol = cfg.get("protocol", "TCP").upper()
        payload_str = cfg.get("payload", "Test Payload")
        self.payload = payload_str.encode("utf-8")
        self.interval = float(cfg.get("interval", 1.0))
        self.count = int(cfg.get("count", 0))  # 0 = infinite
        self.running = True


    def build_packet(self):
        """Craft a packet based on parameters."""
        ip_layer = IP(dst=self.dst_ip)

        if self.protocol == "TCP":
            transport_layer = TCP(dport=self.dst_port, sport=12345, flags="PA")
        elif self.protocol == "UDP":
            transport_layer = UDP(dport=self.dst_port, sport=12345)
        else:
            raise ValueError("Unsupported protocol: choose TCP or UDP")

        return ip_layer / transport_layer / Raw(self.payload)

    def run(self):
        """Thread loop: send packets at intervals."""
        sent = 0
        while self.running and (self.count == 0 or sent < self.count):
            pkt = self.build_packet()
            send(pkt, verbose=False)
            print(f"[TrafficGenerator] Sent packet to {self.dst_ip}:{self.dst_port} | Payload={self.payload}")
            sent += 1
            time.sleep(self.interval)

    def stop(self):
        """Stop the thread gracefully."""
        self.running = False


    @staticmethod
    def generate_from_file(json_file: str):
        """
        Static method: load multiple configs from a JSON file,
        create TrafficGenerator instances, and execute them.
        """
        with open(json_file, "r") as f:
            configs = json.load(f)

        generators = []
        for cfg in configs:
            gen = TrafficGenerator(cfg)
            gen.start()
            generators.append(gen)

        # Wait for all threads to finish
        for gen in generators:
            gen.join()

        print("All traffic generators complete.")
