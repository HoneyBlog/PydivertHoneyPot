import logging
import pydivert
import socket
import threading
from time import time

from thread_safe_dict import ThreadSafeDict
from HoneyPotAnalyze.AttackerLogger import AttackerLogger
from Attacks.Sql_Injection import check_sql_injection
from Attacks.Dos_attack import is_blacklisted, detect_syn_flood

from logger_config import CustomLogger  

# Initialize the dictionary for storing original senders and the honeypot logger
original_senders = ThreadSafeDict()
honeypot_logger = AttackerLogger()

# Initialize custom logger
logger = CustomLogger().get_logger()

def send_to_honeypot(http_request, connection_id):
    """Send HTTP request to the honeypot server and handle the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", 8001))
            src_ip, src_port = sock.getsockname()
            sock.sendall(http_request)
            logging.info(f"HTTP request sent to honeypot from {src_ip}:{src_port}.")
            
            response = sock.recv(4096)
            logging.info(f"Received response from honeypot: {response.decode('utf-8')}")
            send_response_to_original_sender(connection_id, response)
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to send HTTP request to honeypot server: {e}")


def send_response_to_original_sender(identifier, response):
    """Send response back to the original client."""
    try:
        original_packet = original_senders.get(identifier)
        if not original_packet:
            logging.error(f"No original packet found for identifier: {identifier}")
            return

        response_packet = original_packet
        response_packet.tcp.payload = response

        with pydivert.WinDivert() as w:
            w.send(response_packet)
            logging.info(f"Response sent back to original sender at {original_packet.src_addr}:{original_packet.src_port}.")
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to send response to original sender: {e}")
    except Exception as e:
        logging.error(f"An error occurred while sending response to original sender: {e}")


def process_packet(packet, w):
    """Process a captured packet."""
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
            connection_id = f"{packet.src_addr}:{packet.src_port}"
            original_senders.set(connection_id, packet)
            honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
            send_to_honeypot(packet.raw, connection_id)
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
    except Exception as e:
        logging.error(f"An error occurred in listen_on_port_8000: {e}")

if __name__ == "__main__":
    thread_8000 = threading.Thread(target=listen_on_port_8000, daemon=True)
    thread_8000.start()
    thread_8000.join()
