# Network Scanner

## Features
- Supports both ARP and ICMP scanning methods
- Auto-detects local network if no network specified
- Displays IP addresses, MAC addresses, and hostnames
- Command-line arguments for customization

## Requirements
- Python 3.x
- `scapy` library (install with `pip install scapy`)

## Usage

### ARP Scan (default, requires sudo)
```bash
sudo python3 main.py
```
### ICMP Scan
```bash
sudo python3 main.py -m icmp
```
### Scan Specific Network
```bash
sudo python3 main.py -n 192.168.0.0/24
```
