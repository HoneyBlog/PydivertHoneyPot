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
    """
    Sends payload to the honeypot server using a high-level socket connection.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the honeypot server
            s.connect(("127.0.0.1", 8001))
            # Get source IP and port
            src_ip, src_port = s.getsockname()
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            # Send the payload
            s.sendall(payload)
            logging.info(f"Payload sent from {src_ip}:{src_port}.")
            # Optionally, read the response
            response = s.recv(1024)
            logging.info(f"Received response: {response.decode('utf-8')}")
            send_response_to_original_sender(connection_id, response)
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Failed to send payload to honeypot server: {e}")
        


def send_response_to_original_sender(identifier, response):
    """
    Sends a response back to the client that originally sent the packet.
    """
    try:
        original_address = original_senders.get(identifier)  # Assuming this returns a tuple (IP, port)
        if original_address is None:
            logging.error(f"No original sender found for identifier: {identifier}")
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(original_address)
            if isinstance(response, str):
                response = response.encode('utf-8')
            s.sendall(response)
            logging.info(f"Response sent back to original sender at {original_address[0]}:{original_address[1]}.")

    except socket.error as e:
        logging.error(f"Socket error when trying to connect to {original_address}: {e}")
    except Exception as e:
        logging.error(f"Failed to send response to original sender: {e}")



def send_to_honeypot_threaded(payload):
    """
    Wrapper function to send payload to the honeypot in a separate thread.
    """
    thread = threading.Thread(target=send_to_honeypot, args=(payload,))
    thread.start()

        
def listen_on_port_8000():
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter) as w:
            logging.info("Listening on port 8000 and forwarding packets...")
            for packet in w:
                src_ip = packet.src_addr
                if is_blacklisted(src_ip):
                    logging.info(f"Dropping packet from blacklisted IP {src_ip}")
                    continue
                
                if packet.tcp and packet.tcp.syn:
                    if detect_syn_flood(src_ip, time()):
                        logging.warning(f"SYN flood attack detected from {src_ip}. Dropping packet.")
                        continue
                
                payload = packet.tcp.payload
                if payload:
                    payload_str = payload.decode(errors="ignore")
                    if packet.is_outbound:
                        logging.info("Outbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
                    else:
                        logging.info("Inbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
                    logging.info(f"Payload: {payload_str}")

                    if check_sql_injection(payload_str):
                        logging.info("SQL injection detected. Forwarding to honeypot server.")
                        connection_id = f"{packet.src_addr}:{packet.src_port}-{packet.dst_addr}"
                        logging.info(f"connection_id: {connection_id}")

                        original_senders.set(connection_id, (packet.src_addr, packet.src_port))
                        honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
                        send_to_honeypot(payload, connection_id)
                    else:
                        w.send(packet)
                else:
                    w.send(packet)
    except pydivert.WinDivertError as e:
        logging.error(f"WinDivert error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Stopped packet capture.")
        

# def listen_on_port_8001():
#     filter = "tcp.DstPort == 8001 or tcp.SrcPort == 8001"
#     with pydivert.WinDivert(filter) as w:
#         logging.info("Listening on port 8001 for honeypot responses...")
#         for packet in w:
#             response_connection_id = f"{packet.dst_addr}:{packet.dst_port}-{packet.src_addr}:{packet.src_port}"
#             original_sender = original_senders.get(response_connection_id)
#             if original_sender:
#                 packet.dst_addr, packet.dst_port = original_sender
#                 packet.src_port = 8000
#                 w.send(packet)
#                 original_senders.remove(response_connection_id)

if __name__ == "__main__":
    thread_8000 = threading.Thread(target=listen_on_port_8000, daemon=True)
    # thread_8001 = threading.Thread(target=listen_on_port_8001, daemon=True)
    thread_8000.start()
    # thread_8001.start()
    thread_8000.join()
    # thread_8001.join()
    
    
    
    

        
        