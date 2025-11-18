# Intrusion Detection System (IDS)

## Overview
This project implements a **modular Intrusion Detection System (IDS)** designed for educational and research purposes. It performs **packet inspection**, analyzing both **headers** and **payloads** to detect anomalies, suspicious patterns, and potential attacks.  

The system is built with **Python** and leverages libraries like **Scapy** for packet capture and analysis. Its architecture emphasizes **clean code organization**, **extensibility**, and **cross-platform compatibility**.


## Requirements

- Python 3.8+
- Admin/root privileges (required for packet capture)

## Setup

### Windows

1. Install Npcap from https://npcap.com/#download
   - During install, check "Install Npcap in WinPcap API-compatible Mode"

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run as Administrator:
   ```
   python main.py
   ```

### macOS

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run with sudo:
   ```
   sudo python main.py
   ```

### Linux

1. Install libpcap (if not already installed):
   ```
   sudo apt install libpcap-dev
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run with sudo:
   ```
   sudo python main.py
   ```

## Configuration

Edit `config.json` to add your filtering rules:

```json
{
    "filtering_rules": [
        {
            "action": "block",
            "src_ip": "192.168.1.100",
            "description": "Block suspicious host"
        },
        {
            "action": "allow",
            "dst_port": 443,
            "protocol": "tcp",
            "description": "Allow HTTPS"
        }
    ]
}
```

## Testing

Generate traffic to test your rules:

```
ping 127.0.0.1          # ICMP traffic
curl http://localhost   # HTTP traffic
```

Check `alerts.log` for results.

Press Ctrl+C to stop and see statistics.