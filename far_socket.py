import socket
import struct


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(1)
    s.bind(('0.0.0.0', 9999))

    while True:
        data = "sent from laptop - multicast"
        s.sendto(data.encode('utf-8'), ('239.1.1.2', 8888))
        print(F"sent data to 239.1.1.2:8888")
        try:
            data, addr = s.recvfrom(1024)
            print(f"Received from {addr}: {data.decode()}")
        except TimeoutError:
            pass

