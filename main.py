import logging
import pydivert
import socket
from Attacks.Sql_Injection import check_sql_injection
import threading
from thread_safe_dict import ThreadSafeDict
from HoneyPotAnalyze.AttackerLogger import AttackerLogger

# Initialize the dictionary for storing original senders
original_senders = ThreadSafeDict()
honeypot_logger = AttackerLogger()

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def send_to_honeypot(payload):
    """
    Sends payload to the honeypot server using a high-level socket connection.
    """
    dest_ip = "127.0.0.1"
    dest_port = 8001
    logging.info("is in send_to_honeypot")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the honeypot server
            logging.info("before connected")
            s.connect((dest_ip, dest_port))
            # Get source IP and port
            logging.info("after connected")
            src_ip, src_port = s.getsockname()
            # Ensure payload is in bytes
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            logging.info("after payload")

            # Send the payload
            s.sendall(payload)
            logging.info(f"Payload sent from {src_ip}:{src_port} to {dest_ip}:{dest_port}.")
            # Optionally, read the response
            # response = s.recv(1024)
            # logging.info(f"Received response: {response.decode('utf-8')}")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Failed to send payload to honeypot server: {e}")
        
        
def listen_on_port_8000():
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    try:
        with pydivert.WinDivert(filter) as w:
            logging.info("Listening on port 8000 and forwarding packets...")
            for packet in w:
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
                        connection_id = f"{packet.src_addr}:{packet.src_port}-{packet.dst_addr}:{packet.dst_port}"
                        original_senders.set(connection_id, (packet.src_addr, packet.src_port))
                        honeypot_logger.log_attacker_info(packet.src_addr, packet.src_port, "SQL Injection", payload_str)
                        send_to_honeypot(payload)
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
        

def listen_on_port_8001():
    filter = "tcp.SrcPort == 8001"
    with pydivert.WinDivert(filter) as w:
        logging.info("Listening on port 8001 for honeypot responses...")
        for packet in w:
            response_connection_id = f"{packet.dst_addr}:{packet.dst_port}-{packet.src_addr}:{packet.src_port}"
            original_sender = original_senders.get(response_connection_id)
            if original_sender:
                packet.dst_addr, packet.dst_port = original_sender
                packet.src_port = 8000
                w.send(packet)
                original_senders.remove(response_connection_id)

if __name__ == "__main__":
    thread_8000 = threading.Thread(target=listen_on_port_8000)
    thread_8001 = threading.Thread(target=listen_on_port_8001)

    thread_8000.start()
    thread_8001.start()

    thread_8000.join()
    thread_8001.join()
    
    
    
    
    
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
#                 if payload:
#                     payload_str = payload.decode(errors="ignore")
#                     if packet.is_outbound:
#                         logging.info("Outbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
#                     else:
#                         logging.info("Inbound packet captured - %s:%d -> %s:%d" % (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))
#                     logging.info(f"Payload: {payload_str}")

#                     if check_sql_injection(payload_str):
#                         logging.info("SQL injection detected. Forwarding to honeypot server.")
#                         connection_id = f"{packet.src_addr}:{packet.src_port}-{packet.dst_addr}:{packet.dst_port}"
#                         original_senders[connection_id] = (packet.src_addr, packet.src_port)
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
        
        