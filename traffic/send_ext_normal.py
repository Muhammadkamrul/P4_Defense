from scapy.all import get_if_hwaddr, TCP, sendp
import time
from scapy.layers.inet6 import IPv6, Ether
import psutil
import socket

# Parameters
INTERFACE = "eth0"
DST_PORT = 80

def get_ipv6_address(interface_name):
    try:
        addresses = psutil.net_if_addrs()
        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:
                ipv6_address = address.address.split('%')[0]  # Remove zone index if present
                if ipv6_address.startswith("2001"):
                    return ipv6_address

        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def send_normal_traffic(target_ip, target_port, interval=0.5, count=1066):
    src_ipv6 = get_ipv6_address(INTERFACE)
    if src_ipv6 is None:
        print("Error: No valid IPv6 address found.")
        return

    print(f"Using source IPv6: {src_ipv6}")

    for i in range(count):
        packet = Ether(src=get_if_hwaddr(INTERFACE), dst="02:01:01:01:00:01") / \
                 IPv6(src=src_ipv6, dst=target_ip) / \
                 TCP(dport=DST_PORT, flags="S", options=[("Timestamp", (1000, 0))]) # Timestamp.tsval = 1000 = benign

        sendp(packet, iface=INTERFACE, verbose=False)  # Ensure packets are sent via the correct interface
        time.sleep(0.21)

if __name__ == "__main__":
    send_normal_traffic("2001:db8:1::1", 80)
