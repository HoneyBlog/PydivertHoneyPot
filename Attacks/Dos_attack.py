import logging
import subprocess
from collections import defaultdict
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SYN_FLOOD_THRESHOLD = 50  # Number of SYN packets
SYN_FLOOD_TIMEFRAME = 5  # Timeframe in seconds

syn_packets = defaultdict(list)

blocked_file = "blocked_ips.txt"
def add_ip_to_blacklist_file(ip):
    with open(blocked_file, mode='a') as file:
        file.write(ip + '\n')
    logging.info(f"Added {ip} to blacklist")

        
def is_blacklisted(ip):
    try:
        with open(blocked_file, 'r') as file:
            for line in file:
                if ip in line.strip():
                    return True
        return False
    except Exception as e:
        logging.error(f"An error occurred while checking if IP {ip} is blocked: {e}")

def block_ip(ip):
    """
    Blocks the specified IP address
    """
    try:
        add_ip_to_blacklist_file(ip)
        syn_packets.pop(ip)
    except Exception as e:
        logging.error(f"An error occurred while blocking IP {ip}: {e}")


def detect_syn_flood(src_ip, timestamp):
    """
    Detects SYN flood attacks based on the number of SYN packets received
    from an IP within a given timeframe.
    """
    if is_blacklisted(src_ip):
        return True  # IP is already blacklisted

    syn_packets[src_ip].append(timestamp)
    syn_packets[src_ip] = [t for t in syn_packets[src_ip] if timestamp - t < SYN_FLOOD_TIMEFRAME]

    if len(syn_packets[src_ip]) > SYN_FLOOD_THRESHOLD:
        block_ip(src_ip)
        logging.warning(f"SYN flood detected from {src_ip}. IP blocked. Packet count: {len(syn_packets[src_ip])}")
        return True
    return False
