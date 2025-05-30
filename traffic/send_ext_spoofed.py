import socket
import psutil
from scapy.all import sendp, get_if_hwaddr, conf
from scapy.layers.inet6 import Ether, IPv6, TCP
from time import sleep, time
import random

# Parameters
PACKET_COUNT = 1000
HOST_COUNT_PER_NETWORK = 20
INTERFACE = "eth0"
SRC_MAC_ADDRESS = get_if_hwaddr(INTERFACE)
DST_MAC_ADDRESS = "02:01:01:01:00:01"
DST_IP = "2001:db8:1::1"
DST_PORT = 80
random.seed(100)

SRC_NETWORKS = (
    "2001:db8:2::",
    "2001:db9:1::",
    "2001:dba:0:100::",
    "2001:dbb:0:100::",
    "2001:dbc:0:1::",
)

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

def send_tcp_packet(spoofed_src_ip: str):
    # Define Ethernet layer
    eth = Ether(src=SRC_MAC_ADDRESS, dst=DST_MAC_ADDRESS)

    # Define IPv6 layer
    ipv6 = IPv6(src=spoofed_src_ip, dst=DST_IP)

    # Define TCP layer
    tcp = TCP(dport=DST_PORT, flags="S", options=[("Timestamp", (2000, 0))]) # external spoofing 

    # Stack layers and send packet
    packet = eth / ipv6 / tcp
    sendp(packet)

def generate_src_ipv6_addresses(host_count_per_network: int, src_networks: tuple):
    for network in src_networks:
        for i in range(1, host_count_per_network + 1):
            yield f"{network}{i:x}"

if __name__ == "__main__":
    current_src_ip = get_ipv6_address(INTERFACE)
    ips_to_spoof = list(generate_src_ipv6_addresses(HOST_COUNT_PER_NETWORK, SRC_NETWORKS))
    ips_to_spoof.remove(current_src_ip)

    for i in range(PACKET_COUNT):
        spoofed_ip = random.choice(ips_to_spoof)
        send_tcp_packet(spoofed_ip)
        sleep(0.21)