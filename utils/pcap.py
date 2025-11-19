#!/usr/bin/env python3
"""
pcap.py - Sniff packets with Scapy and save them to a pcap file.
"""

import os
import time
from scapy.all import wrpcap
from utils.config import load_config

config = load_config()

def save_pcap(packets, outdir=None):
    # Default output directory
    if outdir is None:
        outdir = config["pcap_output_path"]

    os.makedirs(outdir, exist_ok=True)

    # Timestamped filename
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    outfile = os.path.join(outdir, f"capture_{timestamp}.pcap")


    wrpcap(outfile, packets)

