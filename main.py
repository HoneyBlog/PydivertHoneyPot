import logging
import pydivert
import socket
import threading
from time import time

from HoneyPotAnalyze.AttackerLogger import AttackerLogger
from Attacks.Sql_Injection import check_sql_injection
from Attacks.Dos_attack import is_blacklisted, detect_syn_flood

# Initialize the honeypot logger
honeypot_logger = AttackerLogger()

# Initialize logging to console and logs.txt file
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create handlers
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler('logs.txt')

# Set logging format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def forward_payload_to_honeypot_and_return_response(client_socket, payload):
    """Forward payload to the honeypot server and return the response to the client."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as honeypot_socket:
            honeypot_socket.connect(("127.0.0.1", 8001))
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            honeypot_socket.sendall(payload)
            logging.info(f"Payload sent to honeypot.")

            while True:
                response = honeypot_socket.recv(4096)
                if not response:
                    break
                client_socket.sendall(response)
                logging.info(f"Received response from honeypot and sent back to client.")
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to communicate with honeypot server: {e}")

def process_packet(packet, w):
    """Process a captured packet."""
    logging.info(f"Whole packet: {packet}")
    src_ip = packet.src_addr

    if is_blacklisted(src_ip):
        logging.info(f"Dropping packet from blacklisted IP {src_ip}")
        return

    if packet.tcp and packet.tcp.syn:
        if detect_syn_flood(src_ip, time()):
            logging.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
            return

    payload = packet.tcp.payload
    if payload:
        payload_str = payload.decode(errors="ignore")
        logging.info(f"Packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
        logging.info(f"Payload: {payload_str}")

        if check_sql_injection(payload_str):
            logging.info("SQL injection detected. Forwarding to honeypot server.")
            honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
            # Create a client socket to communicate with the original client
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((packet.src_addr, packet.src_port))
                forward_payload_to_honeypot_and_return_response(client_socket, payload)
        else:
            w.send(packet)
    else:
        w.send(packet)

def listen_on_port_8000():
    """Listen on port 8000 and process incoming packets."""
    filter_str = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter_str) as w:
            logging.info("Listening on port 8000 and forwarding packets...")
            for packet in w:
                process_packet(packet, w)
    except pydivert.WinDivertError as e:
        logging.error(f"An error occurred in listen_on_port_8000: {e}")

if __name__ == "__main__":
    thread_8000 = threading.Thread(target=listen_on_port_8000, daemon=True)
    thread_8000.start()
    thread_8000.join()
