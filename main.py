import socket
import struct
from scapy.all import *
from scapy.all import show_interfaces
from scapy.all import sendp, Ether, IP, IPOption
from scapy.contrib.igmp import IGMP  # IGMP is a contributed module

def remote_subscribe_pc(target_pc_ip:str, target_pc_mac:str,
                        multicast_group:str, interface_index:int):
    traget_iface = conf.ifaces.dev_from_index(interface_index)
    
    # 1. Craft the Ethernet layer with the target's MAC
    eth = Ether(src=target_pc_mac)
    # 2. Craft the IP layer with the target's IP
    # IGMP packets must have a TTL of 1 and the Router Alert option
    router_alert = IPOption(copy_flag=1, optclass=0, option=20, value=b'\x00\x00')
    ip = IP(src=target_pc_ip, dst=multicast_group, ttl=1, options=[router_alert]) # options=[IPOption_Router_Alert()]
    # 3. Craft the IGMP Join (Type 0x16 for IGMPv2)
    igmp = IGMP(type=0x16, gaddr=multicast_group)
    print(f"Sending fake join for {target_pc_ip} on interface index {interface_index}...")
    sendp(eth/ip/igmp, iface=traget_iface) # Replace eth0 with your interface name

if __name__ == "__main__":
    show_interfaces()
    remote_subscribe_pc(target_pc_ip='192.168.0.200',
                        target_pc_mac='04:7C:16:80:A5:71',
                        multicast_group='239.1.1.1',
                        interface_index=2)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(2)
    s.bind(('0.0.0.0', 8888))

    mreq = struct.pack('4sl', socket.inet_aton('224.0.0.1'), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data_multicast = "sent from laptop - multicast"
        data_unicast = "sent from laptop - unicast"
        s.sendto(data_unicast.encode('utf-8'), ('192.168.0.200', 9999))
        s.sendto(data_multicast.encode('utf-8'), ('224.0.0.1', 9999))
        try:
            data, addr = s.recvfrom(1024)
            print(f"Received from {addr}: {data.decode()}")
        except TimeoutError:
            pass

