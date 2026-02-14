import socket
import struct
from scapy.all import *
from scapy.all import show_interfaces, getmacbyip
from scapy.all import sendp, Ether, IP, IPOption
from scapy.contrib.igmp import IGMP  # IGMP is a contributed module
from scapy.all import *
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mr

MULTICAST_GROUP = '239.1.1.1'
TARGET_IP = '192.168.0.254'
LOCAL_PC_IP = '192.168.0.200'
INTERFACE_INDEX = 10

def get_iface_by_ip(target_ip):
    # conf.ifaces contains all interface objects
    for iface_name in conf.ifaces:
        iface = conf.ifaces[iface_name]
        if iface.ip == target_ip:
            return iface
    return None

def get_multicast_mac_subscribe(ip_address):
    """Calculates the Ethernet Multicast MAC for a given IPv4 multicast address."""
    ip_octets = [int(octet) for octet in ip_address.split('.')]
    # Take the last 23 bits of the IP address
    mac_bytes = [0x01, 0x00, 0x5e, ip_octets[1] & 0x7f, ip_octets[2], ip_octets[3]]
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def remote_subscribe_v2(target_pc_ip, multicast_group, iface_obj):
    print(f"[*] Sending IGMPv2 Join (Membership Report) for {target_pc_ip} to {multicast_group}...")

    v2_dest_ip = multicast_group
    eth = Ether(src=getmacbyip(target_pc_ip))
    # Scapy can auto-calculate the dst MAC for multicast IPs if not provided,
    # but manually it's usually 01:00:5e:xx:xx:xx based on the IP.

    # IP Header with Router Alert option (required by many routers for IGMP)
    ip = IP(src=target_pc_ip, dst=v2_dest_ip, ttl=1, options=[IPOption_Router_Alert()])

    # IGMPv2 Membership Report: Type 0x16
    # gaddr is the multicast group address you are joining
    igmp = IGMP(type=0x16, gaddr=multicast_group)

    packet_stack = eth / ip / igmp
    sendp(packet_stack, iface=iface_obj, verbose=False)

def remote_subscribe_v3(target_pc_ip, multicast_group, iface_obj):
    print(f"[*] Sending verified IGMPv3 Join for {target_pc_ip} to {multicast_group}...")

    v3_dest_mac = "01:00:5e:00:00:16"
    v3_dest_ip = "224.0.0.22" # IGMPv3 Reports always go to 224.0.0.22

    eth = Ether(src=getmacbyip(target_pc_ip), dst=v3_dest_mac)
    ip = IP(src=target_pc_ip, dst=v3_dest_ip, ttl=1, options=[IPOption_Router_Alert()])

    # We use IGMPv3 for the header and IGMPv3mr for the report body
    igmp_header = IGMPv3(type=0x22)
    # rtype=4 is 'CHANGE_TO_EXCLUDE_MODE' (effectively a Join)
    group_record = IGMPv3gr(rtype=4, maddr=multicast_group)
    igmp_body = IGMPv3mr(records=[group_record])
    
    packet_stack = eth / ip / igmp_header / igmp_body
    sendp(packet_stack, iface=iface_obj, verbose=False)

def remote_unsubscribe_v3(target_pc_ip, multicast_group, iface_obj):
    print(f"[*] Sending verified IGMPv3 Leave (Unsubscribe) for {target_pc_ip} from {multicast_group}...")

    v3_dest_mac = "01:00:5e:00:00:16"
    v3_dest_ip = "224.0.0.22" 

    eth = Ether(src=getmacbyip(target_pc_ip), dst=v3_dest_mac)
    ip = IP(src=target_pc_ip, dst=v3_dest_ip, ttl=1, options=[IPOption_Router_Alert()])

    # IGMPv3 Header (Type 0x22 is still Membership Report)
    igmp_header = IGMPv3(type=0x22)
    
    # rtype=3 is 'CHANGE_TO_INCLUDE_MODE'
    # With no sources specified, this tells the router to stop forwarding traffic.
    group_record = IGMPv3gr(rtype=3, maddr=multicast_group)
    
    igmp_body = IGMPv3mr(records=[group_record])
    
    packet_stack = eth / ip / igmp_header / igmp_body
    sendp(packet_stack, iface=iface_obj, verbose=False)

def local_subscribe_v3_iaddr(_multicast_group: str, local_ip:str, _socket:socket.socket) -> None:
    mreq = struct.pack('4s4s', socket.inet_aton(_multicast_group), socket.inet_aton(local_ip))
    _socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

def local_unsubscribe_v3(_multicast_group: str, local_ip:str, _socket:socket.socket) -> None:
    mreq = struct.pack('4s4s', socket.inet_aton(_multicast_group), socket.inet_aton(local_ip))
    _socket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)

if __name__ == "__main__":
    show_interfaces()

    my_iface = get_iface_by_ip(LOCAL_PC_IP)
    if my_iface:
        print(f"Found Interface: {my_iface.name}")
        print(f"Description: {my_iface.description}")
        print(f"Index: {my_iface.index}")
    else:
        print("No interface found with that IP.")
        exit()

    # remote_subscribe_v3(TARGET_IP, MULTICAST_GROUP, my_iface)
    # remote_subscribe_v2(TARGET_IP, MULTICAST_GROUP, my_iface)
    remote_unsubscribe_v3(TARGET_IP, MULTICAST_GROUP, my_iface)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(2)
    s.bind(('192.168.0.200', 8888))

    local_subscribe_v3_iaddr("239.1.1.2", '192.168.0.200', s)

    while True:
        data_multicast = "sent from laptop - multicast"
        data_unicast = "sent from laptop - unicast"
        # s.sendto(data_unicast.encode('utf-8'), (TARGET_IP, 9999))
        print('sending multicast')
        s.sendto(data_multicast.encode('utf-8'), (MULTICAST_GROUP, 9999))
        # try:
        #     data, addr = s.recvfrom(1024)
        #     print(f"Received from {addr}: {data.decode()}")
        # except TimeoutError:
        #     pass
        time.sleep(1)
    
    local_unsubscribe_v3('239.1.1.2', '192.168.0.200', s)

