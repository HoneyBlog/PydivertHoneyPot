# import logging
# import pydivert
# import socket
# from Attacks.Sql_Injection import check_sql_injection
# from collections import defaultdict
# from time import time

# # Initialize logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Define threshold and timeframe for SYN flood detection
# SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets
# SYN_FLOOD_TIMEFRAME = 1  # Timeframe in seconds

# # Dictionary to track SYN packets
# syn_packets = defaultdict(list)


# def send_to_honeypot(payload):
#     """
#     Sends payload to the honeypot server using a high-level socket connection.
#     """
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             # Connect to the honeypot server
#             s.connect(("127.0.0.1", 8001))
#             # Send the payload
#             s.sendall(payload)
#             logging.info("Payload sent to honeypot server.")
#     except socket.error as e:
#         logging.error(f"Socket error: {e}")
#     except Exception as e:
#         logging.error(f"Failed to send payload to honeypot server: {e}")

# def detect_syn_flood(src_ip, src_port, timestamp):
#     syn_packets[(src_ip, src_port)].append(timestamp)
#     # Remove old entries
#     syn_packets[(src_ip, src_port)] = [t for t in syn_packets[(src_ip, src_port)] if timestamp - t < SYN_FLOOD_TIMEFRAME]

#     if len(syn_packets[(src_ip, src_port)]) > SYN_FLOOD_THRESHOLD:
#         return True
#     return False


# def main():
#     """
#     Main function to capture and process packets.
#     """
#     # Define the filter for capturing TCP packets on port 8000
#     filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
#     try:
#         with pydivert.WinDivert(filter) as w:
#             logging.info("Listening on port 8000 and forwarding packets...")
#             for packet in w:
#                 payload = packet.tcp.payload
#                 if packet.tcp.syn:
#                     timestamp = time()
#                     src_ip = packet.src_addr
#                     src_port = packet.src_port
#                     if detect_syn_flood(src_ip, src_port, timestamp):
#                         logging.warning("SYN flood attack detected from %s:%d. Dropping packet." % (src_ip, src_port))
#                         continue

#                 if payload:
#                     payload_str = payload.decode(errors="ignore")
#                     if packet.is_outbound:
#                         logging.info("Outbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
#                     else:
#                         logging.info("Inbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
#                     logging.info(f"Payload: {payload_str}")

#                     if check_sql_injection(payload_str):
#                         logging.info("SQL injection detected. Forwarding to honeypot server.")
#                         # Instead of modifying the packet, send the payload directly to the honeypot server
#                         send_to_honeypot(payload)
#                     else:
#                         w.send(packet)
#                 else:
#                     w.send(packet)
#     except pydivert.WinDivertError as e:
#         logging.error(f"WinDivert error: {e}")
#     except Exception as e:
#         logging.error(f"An error occurred: {e}")
#     finally:
#         logging.info("Stopped packet capture.")


# if __name__ == "__main__":
#     main()

import logging
import pydivert
import socket
from Attacks.Sql_Injection import check_sql_injection
from collections import defaultdict
from time import time
import subprocess

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define threshold and timeframe for SYN flood detection
SYN_FLOOD_THRESHOLD = 50  # Number of SYN packets
SYN_FLOOD_TIMEFRAME = 5  # Timeframe in seconds

# Dictionary to track SYN packets
syn_packets = defaultdict(list)
# Set of blacklisted IPs
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
        
def send_to_honeypot(payload):
    """
    Sends payload to the honeypot server using a high-level socket connection.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", 8001))
            s.sendall(payload)
            logging.info("Payload sent to honeypot server.")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Failed to send payload to honeypot server: {e}")

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

def main():
    """
    Main function to capture and process packets.
    """
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter) as w:
            logging.info("Listening on port 8000 and forwarding packets...")
            while True:
                packet = w.recv()
                src_ip = packet.src_addr

                if is_blacklisted(src_ip):
                    logging.info(f"Dropping packet from blacklisted IP {src_ip}")
                    continue

                if packet.tcp and packet.tcp.syn:
                    if detect_syn_flood(src_ip, time()):
                        logging.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
                        continue

                payload = packet.tcp.payload if packet.tcp else None
                if payload:
                    payload_str = payload.decode(errors="ignore")
                    logging.info(f"{'Outbound' if packet.is_outbound else 'Inbound'} packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
                    logging.info(f"Payload: {payload_str}")

                    if check_sql_injection(payload_str):
                        logging.info("SQL injection detected. Forwarding to honeypot server.")
                        send_to_honeypot(payload)
                    else:
                        w.send(packet)
                else:
                    w.send(packet)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Stopped packet capture.")

if __name__ == "__main__":
    main()