import time
from collections import defaultdict
from core.logger import log_alert

# Track ICMP packets per source IP
# Structure: {src_ip: [(timestamp1, timestamp2, ...)]}
icmp_tracker = defaultdict(list)

# Configuration
ICMP_THRESHOLD = 50  # packets per time window
TIME_WINDOW = 10     # seconds

def check_icmp_flood(src_ip):
    """
    Check if source IP is sending too many ICMP packets.
    Returns True if flood detected, False otherwise.
    """
    current_time = time.time()
    
    # Add current packet timestamp
    icmp_tracker[src_ip].append(current_time)
    
    # Remove timestamps older than our time window
    icmp_tracker[src_ip] = [
        ts for ts in icmp_tracker[src_ip] 
        if current_time - ts <= TIME_WINDOW
    ]
    
    # Check if packet count exceeds threshold
    packet_count = len(icmp_tracker[src_ip])
    
    if packet_count > ICMP_THRESHOLD:
        log_alert(
            f"ICMP FLOOD DETECTED: {packet_count} packets in {TIME_WINDOW}s",
            source_ip=src_ip,
            severity="CRITICAL"
        )
        # Clear the tracker for this IP to avoid spam alerts
        icmp_tracker[src_ip] = []
        return True
    
    return False