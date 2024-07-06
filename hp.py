import pydivert
import threading
from queue import Queue
import signal
import sys
import logging
import scapy.all as scapy
import json

# Load configuration from a file
def load_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

config = load_config('config.json')

# Logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("logger.txt"),
    logging.StreamHandler()
])

# Signal handler
def signal_handler(sig, frame):
    logging.info("Signal received, stopping threads...")
    stop_event.set()
    all_packets_queue.put(None)
    honeypot_packets_queue.put(None)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Define packet queues
all_packets_queue = Queue()
honeypot_packets_queue = Queue()
stop_event = threading.Event()

# Define malicious patterns (as bytes)
malicious_patterns = [bytes(pattern, 'utf-8') for pattern in config['malicious_patterns']]

def is_malicious(payload):
    for pattern in malicious_patterns:
        if pattern in payload:
            return True
    return False

# Packet handler for all packets
def all_packets_handler():
    while not stop_event.is_set():
        packet = all_packets_queue.get()
        if packet is None:
            break
        try:
            logging.info("Processing packet in All Packets Handler")
            logging.info(f"Source IP: {packet.src_addr}, Destination IP: {packet.dst_addr}")
            logging.info(f"Source Port: {packet.src_port}, Destination Port: {packet.dst_port}")
            logging.info(f"Protocol: {packet.protocol}, Payload: {packet.payload}")

            if is_malicious(packet.payload):
                logging.info("This is a malicious packet.")
                honeypot_packets_queue.put(packet)
            else:
                logging.info("This is a normal packet. Sending to server on port 8000")
                tcp_packet = scapy.IP(dst=config['server_ip'])/scapy.TCP(dport=config['server_port'], sport=packet.src_port, flags='A')/packet.payload
                scapy.send(tcp_packet)
        except Exception as e:
            logging.error(f"Error processing packet in All Packets Handler: {e}")
        finally:
            all_packets_queue.task_done()

# Packet handler for honeypot packets
def honeypot_handler():
    while not stop_event.is_set():
        packet = honeypot_packets_queue.get()
        if packet is None:
            break
        try:
            logging.info("Processing packet in Honeypot Handler")
            logging.info(f"Source IP: {packet.src_addr}, Destination IP: {packet.dst_addr}")
            logging.info(f"Source Port: {packet.src_port}, Destination Port: {packet.dst_port}")
            logging.info(f"Protocol: {packet.protocol}, Payload: {packet.payload}")

            if packet.tcp.syn:
                logging.info("This is a TCP SYN packet.")
            if packet.tcp.fin:
                logging.info("This is a TCP FIN packet.")
            
            tcp_packet = scapy.IP(dst=config['honeypot_ip'])/scapy.TCP(dport=config['honeypot_port'], sport=packet.src_port, flags='A')/packet.payload
            scapy.send(tcp_packet)
        except Exception as e:
            logging.error(f"Error processing packet in Honeypot Handler: {e}")
        finally:
            honeypot_packets_queue.task_done()

# Main loop to capture and dispatch packets
def main_loop_handler():
    filter = "ip.DstAddr != 127.0.0.2 and (tcp.DstPort != 8000 and tcp.DstPort != 8080)"
    try:
        with pydivert.WinDivert(filter) as w:
            logging.info("WinDivert filter set up successfully")
            for packet in w:
                if stop_event.is_set():
                    break
                logging.info(f"Packet captured: {packet}")
                try:
                    if packet.tcp.syn or packet.tcp.fin:
                        logging.info("SYN or FIN packet detected")
                        w.send(packet)
                    if packet.payload:
                        logging.info(f"Payload detected: {packet.payload}")
                        ack_packet = packet
                        ack_packet.tcp.ack = True
                        ack_packet.tcp.syn = False
                        ack_packet.tcp.fin = False
                        ack_packet.tcp.psh = False
                        ack_packet.tcp.rst = False
                        ack_packet.tcp.seq_num, ack_packet.tcp.ack_num = ack_packet.tcp.ack_num, ack_packet.tcp.seq_num + len(packet.payload)
                        w.send(ack_packet)
                        logging.info("ACK packet sent")

                        all_packets_queue.put(packet)
                        logging.info("Packet added to all_packets_queue")

                except Exception as e:
                    logging.error(f"Error processing packet in Main Loop Handler: {e}")

    except Exception as e:
        logging.error(f"Error setting up WinDivert: {e}")

# Create and start threads
all_packets_thread = threading.Thread(target=all_packets_handler, daemon=True)
honeypot_thread = threading.Thread(target=honeypot_handler, daemon=True)
main_loop_thread = threading.Thread(target=main_loop_handler, daemon=True)

all_packets_thread.start()
honeypot_thread.start()
main_loop_thread.start()

# Join threads
main_loop_thread.join()
all_packets_queue.join()
honeypot_packets_queue.join()
