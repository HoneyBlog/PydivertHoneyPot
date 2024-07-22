import logging
from collections import defaultdict
from utils.ip_detection import IPDetection
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

blocked_file = "blocked_ips.txt"
SYN_FLOOD_THRESHOLD = 50  # Number of SYN packets
SYN_FLOOD_TIMEFRAME = 5  # Timeframe in seconds

syn_packets = defaultdict(list)
blacklist = IPDetection(blocked_file)

def is_blacklisted(ip):
    """
    Checks if the specified IP address is blacklisted
    """
    return blacklist.is_in_list(ip)

def block_ip(ip):
    """
    Blocks the specified IP address
    """
    try:
        blacklist.add_ip_to_list(ip)
        syn_packets.pop(ip)
    except Exception as e:
        logging.error(f"An error occurred while blocking IP {ip}: {e}")


def detect_syn_flood(src_ip, timestamp):
    """
    Detects SYN flood attacks based on the number of SYN packets received
    from an IP within a given timeframe.
    """
    if blacklist.is_in_list(src_ip):
        return True  

    syn_packets[src_ip].append(timestamp)
    syn_packets[src_ip] = [t for t in syn_packets[src_ip] if timestamp - t < SYN_FLOOD_TIMEFRAME]

    if len(syn_packets[src_ip]) > SYN_FLOOD_THRESHOLD:
        block_ip(src_ip)
        logging.warning(f"SYN flood detected from {src_ip}. IP blocked. Packet count: {len(syn_packets[src_ip])}")
        return True
    return False
