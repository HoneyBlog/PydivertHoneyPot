import logging
import pydivert
import socket
import threading
from time import time
from flask import Flask
from flask_socketio import SocketIO, emit

from thread_safe_dict import ThreadSafeDict
from HoneyPotAnalyze.AttackerLogger import AttackerLogger
from Attacks.Sql_Injection import check_sql_injection
from Attacks.Dos_attack import is_blacklisted, detect_syn_flood
from logger_config import CustomLogger  

# Flask and SocketIO setup
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket connections

# Initialize the dictionary for storing original senders and the honeypot logger
original_senders = ThreadSafeDict()
honeypot_logger = AttackerLogger()

# Initialize custom logger
logger = CustomLogger().get_logger()
@socketio.on('connect')
def handle_connect():
    logging.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected')

def send_to_honeypot(payload, connection_id):
    """Send payload to the honeypot server and handle the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", 8001))
            src_ip, src_port = sock.getsockname()
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            sock.sendall(payload)
            logging.info(f"Payload sent to honeypot from {src_ip}:{src_port}.")
            
            response = sock.recv(1024)
            logging.info(f"Received response from honeypot: {response.decode('utf-8')}")
            send_response_to_original_sender(connection_id, response)
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to send payload to honeypot server: {e}")

def send_response_to_original_sender(identifier, response):
    """Send response back to the original client."""
    try:
        original_address = original_senders.get(identifier)
        logging.info(f"Original sender found for identifier {identifier}: {original_address}")
        if not original_address:
            logging.error(f"No original sender found for identifier: {identifier}")
            return
        
        socketio.emit('response', {'data': response.decode('utf-8')})
        logging.info(f"Response sent back to frontend for identifier: {identifier}.")
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to send response to original sender: {e}")

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
            original_senders.set(connection_id, (packet.src_addr, packet.src_port))
            honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
            send_to_honeypot(payload, connection_id)
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
    threading.Thread(target=listen_on_port_8000, daemon=True).start()
    socketio.run(app, host="127.0.0.1", port=8002)
