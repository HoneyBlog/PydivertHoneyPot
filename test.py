from scapy.all import send, IP, TCP

# Normal packet
packet = IP(dst="127.0.0.2")/TCP(dport=8000)/"Normal payload"
send(packet)

# Malicious packet
packet = IP(dst="127.0.0.2")/TCP(dport=8000)/b"bad_pattern1"
send(packet)
