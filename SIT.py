import os
import socket
import sys

def trace_ip(ip_address):
    try:
        target_ip = socket.gethostbyname(ip_address)
        print(f"Tracing route to {ip_address} [{target_ip}]")

        for ttl in range(1, 30):
            receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            receiver.settimeout(1.0)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            receiver.bind(("", 33434))
            sender.sendto(b"", (ip_address, 33434))

            try:
                _, address = receiver.recvfrom(1024)
                address = address[0]
                try:
                    hostname = socket.gethostbyaddr(address)[0]
                except socket.herror:
                    hostname = "Unknown"

                print(f"{ttl}\t{address}\t{hostname}")
                if address == target_ip:
                    break
            except socket.timeout:
                print(f"{ttl}\t*\t*")
            finally:
                receiver.close()
                sender.close()
    except socket.gaierror:
        print("Invalid IP address")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ip_trace.py <ip_address>")
        sys.exit(1)

    ip_address = sys.argv[1]
    trace_ip(ip_address)
