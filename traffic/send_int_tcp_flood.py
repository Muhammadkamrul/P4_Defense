from scapy.all import get_if_hwaddr, TCP, sendp
from scapy.layers.inet6 import IPv6, Ether
import psutil
import socket

# Parameters
INTERFACE = "eth0"
DST_PORT = 80
DST_MAC_ADDRESS = "02:01:01:01:00:01"
PACKET_COUNT = 21000  # Number of packets to send

def get_ipv6_address(interface_name):
    try:
        addresses = psutil.net_if_addrs()
        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:
                ipv6_address = address.address.split('%')[0]  # Remove zone>
                if ipv6_address.startswith("2001"):
                    return ipv6_address

        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def send_bulk_traffic(target_ip, target_port):
    src_ipv6 = get_ipv6_address(INTERFACE)
    if src_ipv6 is None:
        print("Error: No valid IPv6 address found.")
        return

    print(f"Using source IPv6: {src_ipv6}")

    # Generate all packets in a list
    packets = [
        Ether(src=get_if_hwaddr(INTERFACE), dst=DST_MAC_ADDRESS) /
        IPv6(src=src_ipv6, dst=target_ip) /
        TCP(dport=DST_PORT, flags="S", options=[("Timestamp", (6000, 0))]) # internal flooding
        for i in range(PACKET_COUNT)
    ]

    # Send all packets at once
    sendp(packets, iface=INTERFACE, verbose=False, inter=0)  # `inter=0` en>

if __name__ == "__main__":          
	 send_bulk_traffic("2001:db8:1::1", 80)
