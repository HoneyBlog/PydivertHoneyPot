import logging
import subprocess
from collections import defaultdict
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SYN_FLOOD_THRESHOLD = 50  # Number of SYN packets
SYN_FLOOD_TIMEFRAME = 5  # Timeframe in seconds

syn_packets = defaultdict(list)
blacklist = set()

def is_blacklisted(ip):
    return ip in blacklist

def add_to_blacklist(ip):
    blacklist.add(ip)
    logging.info(f"Added {ip} to blacklist")
    
def block_ip(ip):
    """
    Blocks the specified IP address using Windows Firewall via netsh.
    """
    try:
        add_to_blacklist(ip)  # Add IP to blacklist
        # Use netsh to add a firewall rule
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        logging.info(f"Attempting to run command: {command}")
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        logging.info(f"Command output: {result.stdout}")
        logging.info(f"Command error (if any): {result.stderr}")
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args, output=result.stdout, stderr=result.stderr)
        logging.info(f"IP {ip} has been blocked.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip}: {e.stderr}")
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
