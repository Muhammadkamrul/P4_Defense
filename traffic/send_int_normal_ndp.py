from scapy.all import get_if_hwaddr, sendp
import time
from scapy.layers.inet6 import IPv6, Ether, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
import psutil
import socket
from ipaddress import IPv6Address

# Parameters
INTERFACE = "eth0"

def get_global_unique_ipv6(interface_name):
    """Retrieve the link-local IPv6 address of the given interface."""
    try:
        addresses = psutil.net_if_addrs()
        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:
                ipv6_address = address.address
                if ipv6_address.startswith("2001"):
                    return ipv6_address  # Keep the zone index (e.g., fe80::1%eth0)
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def send_ns_packets(target_ip, interval=1, count=556):
    """Send Neighbor Solicitation (NS) packets to a target IPv6 address using link-local address."""
    src_ipv6 = get_global_unique_ipv6(INTERFACE)
    if src_ipv6 is None:
        print("Error: No valid link-local IPv6 address found.")
        return

    src_mac = get_if_hwaddr(INTERFACE)  # Get source MAC address

    # Solicited-node multicast address for target IP

    print(f"Using source IPv6: {src_ipv6}, Source MAC: {src_mac}")

    for i in range(count):
        # Construct NS packet
        packet = (
            Ether(src=src_mac, dst="02:01:01:01:00:01")  # src MAC
            / IPv6(src=src_ipv6, dst=target_ip)
            / ICMPv6ND_NS(tgt=IPv6Address(i+1))  # Target IPv6
        )

        sendp(packet, iface=INTERFACE, verbose=False)
        time.sleep(interval)  # 1-second delay

if __name__ == "__main__":
    send_ns_packets("fe80::1:1ff:fe01:1")  # Target is a link-local IPv6