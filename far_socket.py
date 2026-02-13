import socket
import struct


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind('0.0.0.0', 9999)

    while True:
        data = "sent from laptop - multicast"
        s.sendto(data.encode('utf-8'), ('239.1.1.1', 8888))
        data, addr = s.recvfrom(1024)
        print(f"Received from {addr}: {data.decode()}")

