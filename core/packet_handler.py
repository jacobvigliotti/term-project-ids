from scapy.all import IP, TCP, UDP, ICMP, Raw
from core.packet_analyzer import check_packet
from core.logger import log_alert
from core.dos_detector import check_icmp_flood
from utils.config import load_config

# Load signature rules
config = load_config()
SIGNATURE_RULES = config.get("signature_rules", [])

def check_signatures(payload):
    """
    Check if packet payload matches any signature patterns.
    Returns (matched, description) tuple.
    """
    if not payload:
        return (False, None)
    
    # Convert bytes to string for pattern matching
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
    except:
        payload_str = str(payload)
    
    # Check each signature rule
    for rule in SIGNATURE_RULES:
        pattern = rule.get("pattern", "")
        if pattern and pattern in payload_str:
            description = rule.get("description", "Signature match")
            return (True, description)
    
    return (False, None)

def handle_packet(packet):
    """
    Process each captured packet.
    Extract headers, check against rules, and log the result.
    """

    # Pull out the header info we care about
    header = extract_header(packet)
    
    # Skip packets without IP layer (like ARP)
    # We can't really filter these with IP-based rules
    if header["src_ip"] is None:
        return

    payload = bytes(packet[Raw].load) if Raw in packet else b""

    # Check for signature matches first
    # Note: Only payload-based patterns work. Header-based patterns (TCP flags, packet size) need separate implementation.

    signature_match, signature_desc = check_signatures(payload)
    if signature_match:
        log_alert(f"SIGNATURE DETECTED: {signature_desc} | Payload snippet: {payload[:50]}", 
                  source_ip=header.get("src_ip"), 
                  severity="CRITICAL")
        return  # Stop processing, we already logged it
    
    # Check for ICMP flood
    if header["protocol"] == "icmp":
        if check_icmp_flood(header["src_ip"]):
            return  # Already logged, stop processing
    
    # Check this packet against our filtering rules
    action, reason = check_packet(header)
    
    # Build a message describing the packet
    if header["src_port"]:
        # TCP or UDP packet
        packet_info = (
            f"{header['protocol'].upper()} "
            f"{header['src_ip']}:{header['src_port']} -> "
            f"{header['dst_ip']}:{header['dst_port']}"
        )
    else:
        # ICMP or other protocol without ports
        packet_info = (
            f"{header['protocol'].upper()} "
            f"{header['src_ip']} -> {header['dst_ip']}"
        )
    
    # Log based on action
    if action == "block":
        severity = "WARNING"
        message = f"BLOCKED: {packet_info} | Reason: {reason}"
    else:
        severity = "INFO"
        message = f"ALLOWED: {packet_info} | Reason: {reason}"
    
    log_alert(message, source_ip=header["src_ip"], severity=severity)


def extract_header(packet):
    """
    Pull out header info from a packet.
    Returns a dictionary with the stuff we care about for filtering.
    """
    header = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
    }

    # Check if this packet has an IP layer
    # Not all packets do (like ARP packets)
    if IP in packet:
        header["src_ip"] = packet[IP].src
        header["dst_ip"] = packet[IP].dst
        
        # Figure out what protocol this is
        # The proto field is a number: 6=TCP, 17=UDP, 1=ICMP
        proto_num = packet[IP].proto
        if proto_num == 6:
            header["protocol"] = "tcp"
        elif proto_num == 17:
            header["protocol"] = "udp"
        elif proto_num == 1:
            header["protocol"] = "icmp"
        else:
            header["protocol"] = str(proto_num)

    # TCP and UDP have ports, ICMP doesn't
    if TCP in packet:
        header["src_port"] = packet[TCP].sport
        header["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        header["src_port"] = packet[UDP].sport
        header["dst_port"] = packet[UDP].dport

    return header