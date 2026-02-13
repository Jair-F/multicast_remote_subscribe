import socket
import struct
from scapy.all import *
from scapy.all import show_interfaces
from scapy.all import sendp, Ether, IP, IPOption
from scapy.contrib.igmp import IGMP  # IGMP is a contributed module
from scapy.all import *
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr

MULTICAST_GROUP = '239.1.1.1'
TARGET_IP = '192.168.0.200'
TARGET_MAC = '04:7C:16:80:A5:71'
INTERFACE_INDEX = 2

def get_multicast_mac(ip_address):
    """Calculates the Ethernet Multicast MAC for a given IPv4 multicast address."""
    ip_octets = [int(octet) for octet in ip_address.split('.')]
    # Take the last 23 bits of the IP address
    mac_bytes = [0x01, 0x00, 0x5e, ip_octets[1] & 0x7f, ip_octets[2], ip_octets[3]]
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def remote_subscribe_v3(target_pc_ip, target_pc_mac, multicast_group, iface_obj):
    # IGMPv3 Reports always go to 224.0.0.22
    eth = Ether(src=target_pc_mac, dst=get_multicast_mac(multicast_group))
    ip = IP(src=target_pc_ip, dst="224.0.0.22", ttl=1, options=[IPOption_Router_Alert()])

    # Create a Group Record (type 4 = CHANGE_TO_EXCLUDE_MODE, which is a "Join")
    gr = IGMPv3gr(rtype=4, maddr=multicast_group)
    igmp = IGMPv3(type=0x22, records=[gr])

    sendp(eth/ip/igmp, iface=iface_obj)

if __name__ == "__main__":
    show_interfaces()

    try:
        my_iface = conf.ifaces.dev_from_index(INTERFACE_INDEX)
    except KeyError:
        print("Error: Interface index 2 not found!")
        #exit()

    remote_subscribe_v3(target_pc_ip=TARGET_IP,
                        target_pc_mac=TARGET_MAC,
                        multicast_group=MULTICAST_GROUP,
                        iface_obj=my_iface)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(2)
    s.bind(('0.0.0.0', 8888))

    mreq = struct.pack('4sl', socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data_multicast = "sent from laptop - multicast"
        data_unicast = "sent from laptop - unicast"
        s.sendto(data_unicast.encode('utf-8'), (TARGET_IP, 9999))
        s.sendto(data_multicast.encode('utf-8'), (MULTICAST_GROUP, 9999))
        try:
            data, addr = s.recvfrom(1024)
            print(f"Received from {addr}: {data.decode()}")
        except TimeoutError:
            pass

