import socket
import struct
from scapy.all import *
from scapy.all import show_interfaces
from scapy.all import sendp, Ether, IP, IPOption
from scapy.contrib.igmp import IGMP  # IGMP is a contributed module

MULTICAST_GROUP = '239.1.1.1'
TARGET_IP = '192.168.0.200'
TARGET_MAC = '04:7C:16:80:A5:71'
INTERFACE_INDEX = 2

def remote_subscribe_pc(target_pc_ip:str, target_pc_mac:str,
                        multicast_group:str, iface_obj:int):
    # 1. Craft Layers
    eth = Ether(src=target_pc_mac)
    ra_opt = IPOption(copy_flag=1, optclass=0, option=20, value=b'\x00\x00')
    ip = IP(src=target_pc_ip, dst=multicast_group, ttl=1, options=[ra_opt])
    igmp = IGMP(type=0x16, gaddr=multicast_group)
    
    # 2. Send (using the actual object)
    print(f"[*] Sending spoofed IGMP join for {target_pc_ip}...")
    sendp(eth/ip/igmp, iface=iface_obj, verbose=False)

if __name__ == "__main__":
    show_interfaces()

    try:
        my_iface = conf.ifaces.dev_from_index(INTERFACE_INDEX)
    except KeyError:
        print("Error: Interface index 2 not found!")
        exit()

    remote_subscribe_pc(target_pc_ip=TARGET_IP,
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

