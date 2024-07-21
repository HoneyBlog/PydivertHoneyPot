# import logging
# import pydivert
# import socket
# import threading
# from time import time

# from thread_safe_dict import ThreadSafeDict
# from HoneyPotAnalyze.AttackerLogger import AttackerLogger
# from Attacks.Sql_Injection import check_sql_injection
# from Attacks.Dos_attack import is_blacklisted, detect_syn_flood

# # Initialize the dictionary for storing original senders
# original_senders = ThreadSafeDict()
# honeypot_logger = AttackerLogger()

# # Initialize logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# def send_data(ip, port, data):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.connect((ip, port))
#             s.sendall(data.encode('utf-8') if isinstance(data, str) else data)
#             return s.recv(1024)
#     except socket.error as e:
#         logging.error(f"Socket error when connecting to {ip}:{port} - {e}")
#     except Exception as e:
#         logging.error(f"Unexpected error when sending data to {ip}:{port} - {e}")
#     return None

# def send_to_honeypot(payload, connection_id):
#     response = send_data("127.0.0.1", 8001, payload)
#     if response:
#         send_response_to_original_sender(connection_id, response)

# def send_response_to_original_sender(identifier, response):
#     original_address = original_senders.get(identifier)
#     if original_address:
#         send_data(original_address[0], original_address[1], response)
#     else:
#         logging.error(f"No original sender found for identifier: {identifier}")

# def process_packet(packet):
#     src_ip = packet.src_addr
#     if is_blacklisted(src_ip):
#         logging.info(f"Dropping packet from blacklisted IP {src_ip}")
#         return None

#     if packet.tcp and packet.tcp.syn and detect_syn_flood(src_ip, time()):
#         logging.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
#         return None

#     payload = packet.tcp.payload
#     if payload:
#         payload_str = payload.decode(errors="ignore")
#         logging.info(f"Packet captured - {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
#         logging.info(f"Payload: {payload_str}")

#         if check_sql_injection(payload_str):
#             logging.info("SQL injection detected. Forwarding to honeypot server.")
#             connection_id = f"{packet.src_addr}:{packet.src_port}-{packet.dst_addr}"
#             original_senders.set(connection_id, (packet.src_addr, packet.src_port))
#             honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
#             send_to_honeypot(payload, connection_id)
#             return None
#     return packet

# def listen_on_port_8000():
#     filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
#     try:
#         with pydivert.WinDivert(filter) as w:
#             logging.info("Listening on port 8000 and forwarding packets...")
#             for packet in w:
#                 processed_packet = process_packet(packet)
#                 if processed_packet:
#                     w.send(processed_packet)
#     except pydivert.WinDivertError as e:
#         logging.error(f"WinDivert error: {e}")
#     except Exception as e:
#         logging.error(f"An error occurred: {e}")
#     finally:
#         logging.info("Stopped packet capture.")

# if __name__ == "__main__":
#     thread_8000 = threading.Thread(target=listen_on_port_8000, daemon=True)
#     thread_8000.start()
#     thread_8000.join()


import logging
import pydivert
import socket
import threading
from time import time

from thread_safe_dict import ThreadSafeDict
from HoneyPotAnalyze.AttackerLogger import AttackerLogger
from Attacks.Sql_Injection import check_sql_injection
from Attacks.Dos_attack import is_blacklisted, detect_syn_flood

# Initialize the dictionary for storing original senders
original_senders = ThreadSafeDict()
honeypot_logger = AttackerLogger()

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def send_to_honeypot(payload, connection_id):
    """Sends payload to the honeypot server using a high-level socket connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", 8001))
            src_ip, src_port = s.getsockname()
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            s.sendall(payload)
            logging.info(f"Payload sent to honeypot at port 8001 from {src_ip}:{src_port}.")
            response = s.recv(1024)
            logging.info(f"Received response from honeypot: {response.decode('utf-8')}")
            send_response_to_original_sender(connection_id, response)
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Failed to send payload to honeypot server: {e}")


def send_response_to_original_sender(identifier, response):
    """Sends a response back to the client that originally sent the packet."""
    try:
        original_address = original_senders.get(identifier)
        if original_address is None:
            logging.error(f"No original sender found for identifier: {identifier}")
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(original_address)
            if isinstance(response, str):
                response = response.encode('utf-8')
            s.sendall(response)
            logging.info(f"Response sent back to original sender at {original_address[0]}:{original_address[1]}.")
    except (socket.error, socket.timeout) as e:
        logging.error(f"Failed to send response to original sender: {e}")


def process_packet(packet, w):
    """Process an individual packet."""
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
            connection_id = f"{packet.src_addr}:{packet.src_port}"
            original_senders.set(connection_id, (packet.src_addr, packet.src_port))
            honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
            send_to_honeypot(payload, connection_id)
        else:
            w.send(packet)
    else:
        w.send(packet)


def listen_on_port_8000():
    """Listen on port 8000 and forward packets."""
    filter_str = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter_str) as w:
            logging.info("Listening on port 8000 and forwarding packets...")
            for packet in w:
                process_packet(packet, w)
    except pydivert.WinDivertError as e:
        logging.error(f"An error occurred in listen_on_port_8000: {e}")


def process_honeypot_response(packet, w):
    """Process a response packet from the honeypot."""
    logging.info(f"Whole packet: {packet}")
    response_connection_id = f"{packet.src_addr}:{packet.src_port}"
    original_sender = original_senders.get(response_connection_id)
    if original_sender:
        packet.dst_addr, packet.dst_port = original_sender
        packet.src_port = 8000
        w.send(packet)
        logging.info(f"Sent honeypot response to original sender: {original_sender}")
        original_senders.remove(response_connection_id)
    else:
        logging.warning(f"No original sender found for response: {response_connection_id}")


def listen_on_port_8001():
    """Listen on port 8001 for honeypot responses."""
    filter_str = "tcp.DstPort == 8001 or tcp.SrcPort == 8001"
    try:
        with pydivert.WinDivert(filter_str) as w:
            logging.info("Listening on port 8001 for honeypot responses...")
            for packet in w:
                if packet.is_outbound:
                    process_honeypot_response(packet, w)
                else:
                    w.send(packet)
    except pydivert.WinDivertError as e:
        logging.error(f"An error occurred in listen_on_port_8001: {e}")


if __name__ == "__main__":
    thread_8000 = threading.Thread(target=listen_on_port_8000, daemon=True)
    thread_8001 = threading.Thread(target=listen_on_port_8001, daemon=True)
    thread_8000.start()
    thread_8001.start()
    thread_8000.join()
    # thread_8001.join()
    
    
    
    

        
        