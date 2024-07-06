import pydivert
import threading
from queue import Queue
import signal
import sys
import logging
from collections import defaultdict
import scapy

# Constants
ASSET_ADDR = "127.0.0.2"
ASSET_PORT = 8000
HONEYPOT_ADDR = "127.0.0.2"
HONEYPOT_PORT = 8080

# Logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("logger.txt"),
    logging.StreamHandler()
])

# Data Structures
tcp_streams = defaultdict(lambda: {'seq': 0, 'data': bytearray(), 'acked': 0})
incoming_addr = {}
all_packets_queue = Queue()
asset_packets_queue = Queue()
honeypot_packets_queue = Queue()

# Signal handler
def signal_handler(sig, frame):
    logging.info("Signal received, stopping threads...")
    for queue in [asset_packets_queue, honeypot_packets_queue, all_packets_queue]:
        queue.put(None)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def reassemble_payload(stream_id, packet):
    """
    Reassemble TCP data for a given stream ID.
    """
    stream = tcp_streams[stream_id]
    payload = packet.tcp.payload

    # Append new data to the stream
    if packet.tcp.seq_num == stream['seq']:
        stream['data'].extend(payload)
        stream['seq'] += len(payload)

        # Process payload once it is complete
        if packet.tcp.flags & 0x01:  # Check if it's a FIN flag
            return stream['data']
    else:
        # Handle out-of-order or missing packets if needed
        pass

def is_malicious(payload):
    malicious_patterns = [b"bad_pattern1", b"bad_pattern2"]
    return any(pattern in payload for pattern in malicious_patterns)

def send_packet(destination_ip, destination_port, packet):
    """
    Send packet to the specified destination using scapy.
    """
    ip = scapy.IP(src=packet.ipv4.src_addr, dst=destination_ip)
    tcp = scapy.TCP(sport=packet.tcp.src_port, dport=destination_port,
              seq=packet.tcp.seq_num, ack=packet.tcp.ack_num,
              flags='A' if packet.tcp.flags & 0x10 else '',  # ACK flag
              window=packet.tcp.window_size)
    payload = packet.tcp.payload
    scapy_packet = ip / tcp / payload
    send(scapy_packet, verbose=False)  # `verbose=False` to suppress output

def process_packets(queue, handler):
    """
    Generic packet processing loop.
    """
    while True:
        packet = queue.get()
        if packet is None:
            break
        try:
            handler(packet)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
        finally:
            queue.task_done()

def main_loop_handler():
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 80"
    try:
        with pydivert.WinDivert(filter) as w:
            while True:
                packet = w.recv()
                try:
                    if packet.tcp.syn or packet.tcp.fin:
                        w.send(packet)  # Forward SYN/FIN packets

                    with incoming_addr_lock:
                        if (packet.ipv4.src_addr, packet.tcp.src_port) in incoming_addr:
                            original_dst_addr, original_dst_port = incoming_addr.pop((packet.ipv4.src_addr, packet.tcp.src_port))
                            packet.ipv4.dst_addr = original_dst_addr
                            packet.tcp.dst_port = original_dst_port
                            packet.direction = pydivert.Direction.OUTBOUND
                            w.send(packet)

                    if packet.payload:
                        logging.info(f"Payload: {packet.payload}")
                        ack_packet = packet
                        ack_packet.tcp.ack = True
                        ack_packet.tcp.syn = False
                        ack_packet.tcp.fin = False
                        ack_packet.tcp.psh = False
                        ack_packet.tcp.rst = False
                        ack_packet.tcp.seq_num, ack_packet.tcp.ack_num = ack_packet.tcp.ack_num, ack_packet.tcp.seq_num + len(packet.payload)
                        w.send(ack_packet)
                        all_packets_queue.put(packet)

                except Exception as e:
                    logging.error(f"Error processing packet in Main Loop Handler: {e}")

    except Exception as e:
        logging.error(f"Error setting up WinDivert: {e}")

def asset_handler(packet):
    send_packet(ASSET_ADDR, ASSET_PORT, packet)

def honeypot_handler(packet):
    send_packet(HONEYPOT_ADDR, HONEYPOT_PORT, packet)

def all_packets_handler(packet):
    stream_id = (packet.ipv4.src_addr, packet.tcp.src_port, packet.ipv4.dst_addr, packet.tcp.dst_port)
    if packet.tcp.flags & 0x10:  # ACK flag
        stream_data = reassemble_payload(stream_id, packet)
        if stream_data:
            packet.payload = stream_data

            # Check for malicious patterns
            if is_malicious(packet.payload):
                logging.warning("Malicious pattern detected.")
                honeypot_packets_queue.put(packet)
            else:
                asset_packets_queue.put(packet)

# Start packet processing threads
asset_thread = threading.Thread(target=lambda: process_packets(asset_packets_queue, asset_handler), daemon=True)
honeypot_thread = threading.Thread(target=lambda: process_packets(honeypot_packets_queue, honeypot_handler), daemon=True)
all_packets_thread = threading.Thread(target=lambda: process_packets(all_packets_queue, all_packets_handler), daemon=True)
main_loop_thread = threading.Thread(target=main_loop_handler, daemon=True)

asset_thread.start()
honeypot_thread.start()
main_loop_thread.start()
all_packets_thread.start()

# Join threads and wait for each queue to end its task
main_loop_thread.join()
asset_thread.join()
honeypot_thread.join()
all_packets_queue.join()
