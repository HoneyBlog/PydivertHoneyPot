# import logging
# import pydivert
# import socket
# import threading
# from time import time
# from flask import Flask
# from flask_socketio import SocketIO, emit

# from utils.thread_safe_dict import ThreadSafeDict
# from utils.attacks_logger import AttacksLogger
# from utils.ip_detection import IPDetection
# from rec_attacks.sql_Injection import check_sql_injection
# from rec_attacks.dos_attack import is_blacklisted, detect_syn_flood
# from utils.logger_config import CustomLogger

# assetlist = IPDetection('whitelist.txt')
# blacklist_sql = IPDetection('blacklist_sql.txt')

# # Initialize the dictionary for storing original senders and the honeypot logger
# original_senders = ThreadSafeDict()
# honeypot_logger = AttacksLogger()

# # Initialize custom logger
# logger = CustomLogger().get_logger()

# # Flask and SocketIO setup
# app = Flask(__name__)
# socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket connections

# # Initialize websockets
# @socketio.on('connect')
# def handle_connect():
#     logging.info('Client connected')

# @socketio.on('disconnect')
# def handle_disconnect():
#     logging.info('Client disconnected')


# # Pydivert functions
# def send_to_honeypot(payload, connection_id):
#     """Send payload to the honeypot server and handle the response."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#             sock.connect(("127.0.0.1", 8001))
#             src_ip, src_port = sock.getsockname()
#             if isinstance(payload, str):
#                 payload = payload.encode('utf-8')
#             sock.sendall(payload)
#             logger.info(f"Payload sent to honeypot from {src_ip}:{src_port}.")
            
#             response = sock.recv(1024)
#             logger.info(f"Received response from honeypot: {response.decode('utf-8')}")
#             send_response_to_original_sender(connection_id, response)
#     except (socket.error, socket.timeout) as e:
#         logger.error(f"Failed to send payload to honeypot server: {e}")

# def send_response_to_original_sender(identifier, response):
#     """Send response back to the original client."""
#     try:
#         original_address = original_senders.get(identifier)
#         logger.info(f"Original sender found for identifier {identifier}: {original_address}")
#         if not original_address:
#             logging.error(f"No original sender found for identifier: {identifier}")
#             return
        
#         socketio.emit('response', {'data': response.decode('utf-8')}, room=original_address)
#         logger.info(f"Response sent back to frontend for identifier: {identifier}.")
#     except (socket.error, socket.timeout) as e:
#         logger.error(f"Failed to send response to original sender: {e}")

# def process_packet(packet, w):
#     """Process a captured packet."""
#     src_ip = packet.src_addr

#     if is_blacklisted(src_ip):
#         logger.info(f"Dropping packet from blacklisted IP {src_ip}")
#         return   

#     if packet.tcp and packet.tcp.syn:
#         if detect_syn_flood(src_ip, time()):
#             logger.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
#             honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SYN Flood", "")
#             return

#     payload = packet.tcp.payload
#     if payload:
#         payload_str = payload.decode(errors="ignore")
#         logger.info(f"Packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
#         logger.info(f"Payload: {payload_str}")

#         if blacklist_sql.is_in_list(src_ip) or check_sql_injection(payload_str):
#             if check_sql_injection(payload_str):
#                 honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
#                 if not blacklist_sql.is_in_list(src_ip):
#                     blacklist_sql.add_ip_to_list(src_ip)
#             connection_id = f"{packet.src_addr}:{packet.src_port}"
#             original_senders.set(connection_id, (packet.src_addr, packet.src_port))
#             logger.info("SQL injection or sql blacklist IP detected. Forwarding to honeypot server.")
#             send_to_honeypot(payload, connection_id)
#         else:
#             w.send(packet)
#     else:
#         w.send(packet)


# def listen_on_port_8000():
#     """Listen on port 8000 and process incoming packets."""
#     filter_str = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
#     try:
#         with pydivert.WinDivert(filter_str) as w:
#             logger.info("Listening on port 8000 and forwarding packets...")
#             for packet in w:
#                 process_packet(packet, w)
#     except Exception as e:
#         logger.error(f"An error occurred in listen_on_port_8000: {e}")

# if __name__ == "__main__":
#     threading.Thread(target=listen_on_port_8000, daemon=True).start()
#     socketio.run(app, host="127.0.0.1", port=8002)

import requests
import logging
import pydivert
import socket
import threading
from time import time
from flask import Flask
from flask_socketio import SocketIO, emit

from utils.thread_safe_dict import ThreadSafeDict
from utils.attacks_logger import AttacksLogger
from utils.ip_detection import IPDetection
from rec_attacks.sql_Injection import check_sql_injection
from rec_attacks.dos_attack import is_blacklisted, detect_syn_flood
from utils.logger_config import CustomLogger

blacklist_sql = IPDetection('blacklist_sql.txt')

# Flask and SocketIO setup
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket connections

# Initialize the dictionary for storing original senders and the honeypot logger
original_senders = ThreadSafeDict()
honeypot_logger = AttacksLogger()

# Initialize logging to console and logs.txt file
logger = CustomLogger().get_logger()

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected')

# def send_to_honeypot(payload, connection_id):
#     """Send payload to the honeypot server and handle the response."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#             sock.connect(("127.0.0.1", 8001))
#             src_ip, src_port = sock.getsockname()
#             if isinstance(payload, str):
#                 payload = payload.encode('utf-8')
#             sock.sendall(payload)
#             logger.info(f"Payload sent to honeypot from {src_ip}:{src_port}.")
            
#             response = sock.recv(1024)
#             logger.info(f"Received response from honeypot: {response.decode('utf-8')}")
#             send_response_to_original_sender(connection_id, response)
#     except (socket.error, socket.timeout) as e:
#         logger.error(f"Failed to send payload to honeypot server: {e}")
def send_to_honeypot(payload, connection_id):
    """Send payload to the honeypot server and handle the response."""
    try:
        url = "http://127.0.0.1:8001/api/handle-packet"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=payload, headers=headers)
        logger.info(f"Received response from honeypot: {response.status_code} - {response.text}")
        send_response_to_original_sender(connection_id, response.content)
    except requests.RequestException as e:
        logger.error(f"Failed to send payload to honeypot server: {e}")




def send_response_to_original_sender(identifier, response):
    """Send response back to the original client."""
    try:
        original_address = original_senders.get(identifier)
        logger.info(f"Original sender found for identifier {identifier}: {original_address}")
        if not original_address:
            logger.error(f"No original sender found for identifier: {identifier}")
            return
        
        socketio.emit('response', {'data': response.decode('utf-8')}, namespace='/')
        logger.info(f"Response sent back to frontend for identifier: {identifier}.")
    except (socket.error, socket.timeout) as e:
        logger.error(f"Failed to send response to original sender: {e}")

# def process_packet(packet, w):
#     """Process a captured packet."""
#     src_ip = packet.src_addr
#     connection_id = f"{packet.src_addr}:{packet.src_port}"
#     payload = packet.tcp.payload

#     if is_blacklisted(src_ip):
#         logger.info(f"Dropping packet from blacklisted IP {src_ip}")
#         honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SYN Flood", "")
#         return

#     if packet.tcp and packet.tcp.syn:
#         if detect_syn_flood(src_ip, time()):
#             logger.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
#             return
    
#     if blacklist_sql.is_in_list(src_ip):
#         logger.info("SQL blacklist IP detected. Forwarding to honeypot server.")
#         send_to_honeypot(payload, connection_id)

#     if payload:
#         payload_str = payload.decode(errors="ignore")
#         logger.info(f"Packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
#         logger.info(f"Payload: {payload_str}")

#         original_senders.set(connection_id, (packet.src_addr, packet.src_port))
#         try:
#             if check_sql_injection(payload_str):
#                 honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
#                 if not blacklist_sql.is_in_list(src_ip):
#                     blacklist_sql.add_ip_to_list(src_ip)
#                 logger.info("SQL injection detected. Forwarding to honeypot server.")
#                 send_to_honeypot(payload, connection_id)
#             else:
#                 w.send(packet)
#         except Exception as e:
#             logger.error(f"An error occurred while processing the packet: {e}")
#     else:
#         w.send(packet)
def process_packet(packet, w):
    """Process a captured packet."""
    src_ip = packet.src_addr
    connection_id = f"{packet.src_addr}:{packet.src_port}"
    payload = packet.tcp.payload

    # Check for SYN flood attack
    if packet.tcp and packet.tcp.syn:
        if detect_syn_flood(src_ip, time()):
            logger.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
            return

    # If IP is in blacklist, send payload to honeypot server
    if blacklist_sql.is_in_list(src_ip):
        logger.info("SQL blacklist IP detected. Forwarding to honeypot server.")
        send_to_honeypot(payload, connection_id)
        return

    # If payload exists, process it further
    if payload:
        payload_str = payload.decode(errors="ignore")
        logger.info(f"Packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
        logger.info(f"Payload: {payload_str}")

        original_senders.set(connection_id, (packet.src_addr, packet.src_port))
        try:
            # Check for SQL injection
            if check_sql_injection(payload_str) or '--' in payload_str:
                honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
                if not blacklist_sql.is_in_list(src_ip):
                    blacklist_sql.add_ip_to_list(src_ip)
                logger.info("SQL injection detected. Forwarding to honeypot server.")
                send_to_honeypot(payload, connection_id)
            else:
                w.send(packet)
        except Exception as e:
            logger.error(f"An error occurred while processing the packet: {e}")
    else:
        w.send(packet)







def listen_on_port_8000():
    """Listen on port 8000 and process incoming packets."""
    filter_str = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter_str) as w:
            logger.info("Listening on port 8000 and forwarding packets...")
            for packet in w:
                process_packet(packet, w)
    except Exception as e:
        logger.error(f"An error occurred in listen_on_port_8000: {e}")

if __name__ == "__main__":
    threading.Thread(target=listen_on_port_8000, daemon=True).start()
    socketio.run(app, host="127.0.0.2", port=8002)