from scapy.all import sendp, get_if_hwaddr, conf, send
from scapy.layers.inet6 import Ether, IPv6, ICMPv6ND_NS
from scapy.utils6 import in6_getnsma
import psutil
import socket

# Parameters
PACKET_COUNT = 1
INTERFACE = "eth0"
SRC_MAC_ADDRESS = get_if_hwaddr(INTERFACE)

conf.iface = INTERFACE

def get_ipv6(interface_name, get_global=False):
    try:
        # Get all network interfaces and their addresses
        addresses = psutil.net_if_addrs()

        if interface_name not in addresses:
            raise ValueError(f"Interface '{interface_name}' not found.")

        # Iterate over the addresses of the given interface
        for address in addresses[interface_name]:
            if address.family == socket.AF_INET6:  # Check for IPv6 family
                ipv6_address = address.address.split('%')[0]  # Remove zone index if present
                if ipv6_address.startswith("2001" if get_global else "fe80"):  # Check for global or link-local address
                    return ipv6_address

        # If no matching IPv6 address is found
        return None

    except Exception as e:
        print(f"Error: {e}")
        return None

def send_dad_packet(target_address):
    """
    Send an ICMPv6 Neighbor Solicitation packet to the target address.

    Parameters:
        link_local_addr (str): The link-local address to send the packet for.
    """
    # Get the solicited-node multicast address for the link local address
    solicitated_node_addr_bytes = in6_getnsma(socket.inet_pton(socket.AF_INET6, target_address))

    # Convert the solicited-node address to a string
    solicitated_node_addr = socket.inet_ntop(socket.AF_INET6, solicitated_node_addr_bytes)

    # Create the IPv6 header
    ipv6 = IPv6(src="::", dst=solicitated_node_addr)

    # Create the ICMPv6 Neighbor Solicitation header
    ns = ICMPv6ND_NS(tgt=target_address)

    # Combine the headers to create the packet
    packet = ipv6 / ns

    # Send the packet
    send(packet, iface=INTERFACE, verbose=False)

    print(f"Sent DAD packet for {target_address}.")
    

if __name__ == "__main__":
    packets_sent = 0
    for i in range(PACKET_COUNT):
        # send dad packet for the link local address
        lla_to_check = get_ipv6(INTERFACE, get_global=False)
        lla_found = True
        if lla_to_check is None:
            print("Error: Could not retrieve IPv6 lla.")
            lla_found = False
        if lla_found:
            send_dad_packet(lla_to_check)
            packets_sent += 1
        
        # send dad packet for the global address
        gua_to_check = get_ipv6(INTERFACE, get_global=True)
        gua_found = True
        if gua_to_check is None:
            print("Error: Could not retrieve IPv6 gua.")
            gua_found = False
        if gua_found:
            send_dad_packet(gua_to_check)
            packets_sent += 1
        
    print(f"Total packets sent: {packets_sent}.")