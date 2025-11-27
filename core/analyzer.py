from scapy.all import IP, TCP, UDP, ICMP

def extract_features(packet):
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