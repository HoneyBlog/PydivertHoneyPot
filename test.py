from scapy.all import *

# Define the fake source IP and the target IP
fake_ip = "192.168.1.100"
target_ip = "target.server.ip"  # Replace with the actual target IP
target_port = 8000

# Create the IP layer with the fake source IP
ip = IP(src=fake_ip, dst=target_ip)

# Create the TCP layer for port 8000 and set the SYN flag to initiate a connection
tcp = TCP(dport=target_port, sport=RandShort(), flags='S')

# Create the GET request payload
payload = b"GET / HTTP/1.1\r\nHost: {0}\r\n\r\n".format(target_ip).encode()

# Combine IP, TCP, and payload into one packet
packet = ip/tcp/payload

# Send the packet
send(packet)