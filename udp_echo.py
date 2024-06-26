import socket

UDP_IP = "10.0.2.2"
# UDP_IP = "127.0.0.1"
# UDP_IP = "::1"
UDP_PORT = 80

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)
    print("Received message:", data.decode())
    sock.sendto(data, addr)
