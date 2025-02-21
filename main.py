import socket
import ipaddress
import argparse
from dataclasses import dataclass
from typing import List, Optional
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1

@dataclass
class NetworkDevice:
    ip: str
    mac: str
    hostname: Optional[str] = None

class NetworkScanner:
    def __init__(self):
        self.local_ip = self._get_local_ip()

    @staticmethod
    def _get_local_ip() -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
            except Exception:
                return "127.0.0.1"

    def _get_local_mac(self) -> str:
        try:
            import netifaces
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return netifaces.ifaddresses(default_interface)[netifaces.AF_LINK][0]['addr']
        except Exception:
            return "Local Machine"

    @staticmethod
    def get_hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def arp_scan(self, network: str) -> List[NetworkDevice]:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=2, verbose=0)[0]
        
        return [
            NetworkDevice(ip=received.psrc, mac=received.hwsrc)
            for sent, received in result
        ]

    def icmp_scan(self, network: str) -> List[NetworkDevice]:
        net = ipaddress.IPv4Network(network, strict=False)
        devices = []

        for ip in net.hosts():
            ip_str = str(ip)
            packet = IP(dst=ip_str)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            if response:
                devices.append(NetworkDevice(ip=ip_str, mac=getattr(response, 'hwsrc', 'N/A')))
        
        return devices

    def scan_network(self, method: str = 'arp', network: Optional[str] = None) -> List[NetworkDevice]:
        if not network:
            network = f"{self.local_ip}/24"
        
        net = ipaddress.IPv4Network(network, strict=False)
        print(f"Scanning {net} using {method.upper()}...")

        # Perform scan based on method
        devices = self.arp_scan(str(net)) if method == 'arp' else self.icmp_scan(str(net))

        # Add local machine if not already in results
        if not any(device.ip == self.local_ip for device in devices):
            devices.append(NetworkDevice(
                ip=self.local_ip,
                mac=self._get_local_mac()
            ))

        # Add hostnames
        for device in devices:
            device.hostname = self.get_hostname(device.ip)

        return devices

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-m", "--method", choices=['arp', 'icmp'], default='arp',
                      help="Scanning method (arp/icmp)")
    parser.add_argument("-n", "--network", help="Network in CIDR (e.g., 192.168.1.0/24)")
    args = parser.parse_args()

    scanner = NetworkScanner()
    devices = scanner.scan_network(args.method, args.network)

    # Display results
    print("\nActive Devices:")
    print("IP Address\t\tMAC Address\t\tHostname")
    print("----------------------------------------------------------")
    for device in devices:
        print(f"{device.ip}\t{device.mac}\t{device.hostname}")

if __name__ == "__main__":
    main()