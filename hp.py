import pydivert
import threading
from queue import Queue
import signal
import sys
import logging

# Logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("logger.txt"),
    logging.StreamHandler()
])

# Signal handler
def signal_handler(sig, frame):
    logging.info("Signal received, stopping threads...")
    all_packets_queue.put(None)
    honeypot_packets_queue.put(None)
    sys.exit(0)
    
signal.signal(signal.SIGINT, signal_handler)

# Define packet queues
all_packets_queue = Queue()
honeypot_packets_queue = Queue()

# Define malicious patterns (as bytes)
malicious_patterns = [b"bad_pattern1", b"bad_pattern2"]  # Define actual patterns

def is_malicious(payload):
    for pattern in malicious_patterns:
        if pattern in payload:
            return True
    return False

# Packet handler for all packets
def all_packets_handler():
    while True:
        packet = all_packets_queue.get()
        if packet is None:
            break
        try:
            # Process all packets
            print("All Packets Handler")
            print(f"Source IP: {packet.src_addr}")
            print(f"Destination IP: {packet.dst_addr}")
            print(f"Source Port: {packet.src_port}")
            print(f"Destination Port: {packet.dst_port}")
            print(f"Protocol: {packet.protocol}")
            print(f"Payload: {packet.payload}")

            # Check if the packet is malicious
            if is_malicious(packet.payload):
                print("This is a malicious packet.")
                honeypot_packets_queue.put(packet)
            else:
                print("This is a normal packet.")
                # Send to server 8000
                # Here, you'll need to send the packet to the server on port 8000
        except Exception as e:
            logging.error(f"Error processing packet in All Packets Handler: {e}")
        finally:
            all_packets_queue.task_done()

# Packet handler for honeypot packets
def honeypot_handler():
    while True:
        packet = honeypot_packets_queue.get()
        if packet is None:
            break
        try:
            # Process honeypot-specific packets
            print("Honeypot Handler")
            print(f"Source IP: {packet.src_addr}")
            print(f"Destination IP: {packet.dst_addr}")
            print(f"Source Port: {packet.src_port}")
            print(f"Destination Port: {packet.dst_port}")
            print(f"Protocol: {packet.protocol}")
            print(f"Payload: {packet.payload}")

            # Check if the packet is a TCP SYN or FIN
            if packet.tcp.syn:
                print("This is a TCP SYN packet.")
            if packet.tcp.fin:
                print("This is a TCP FIN packet.")
            
            # Send to honeypot server 8080
            # Here, you'll need to send the packet to the honeypot server on port 8080

        except Exception as e:
            logging.error(f"Error processing packet in Honeypot Handler: {e}")
        finally:
            honeypot_packets_queue.task_done()

# Main loop to capture and dispatch packets
def main_loop_handler():
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 80"
    try:
        with pydivert.WinDivert(filter) as w:
            for packet in w:
                try:
                    if packet.tcp.syn or packet.tcp.fin:
                        w.send(packet)

                    # send ACK and add to all packets queue
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
