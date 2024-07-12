import pydivert
import socket
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to forward the packet to the backend on port 8000
def forward_packet(data):
    backend_host = '127.0.0.1'
    backend_port = 8000
    try:
        # Create a socket connection to the backend
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30)  # Increase timeout duration
            s.connect((backend_host, backend_port))
            s.sendall(data)
            logging.info(f"Data sent to backend: {data}")
            response = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                response += part
            logging.info(f"Packet forwarded to backend on port {backend_port} with response: {response}")
            return response
    except socket.timeout:
        logging.error("Timeout occurred while forwarding packet to backend")
        return None
    except Exception as e:
        logging.error(f"Failed to forward packet to backend on port {backend_port}: {e}")
        return None

# Function to handle OPTIONS requests separately
def handle_options_request(packet):
    options_response = b"HTTP/1.1 204 No Content\r\n" \
                       b"Access-Control-Allow-Origin: *\r\n" \
                       b"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n" \
                       b"Access-Control-Allow-Headers: Content-Type, Authorization\r\n" \
                       b"\r\n"
    packet.tcp.payload = options_response
    return packet

# Function to reconstruct HTTP request from packets
def reconstruct_http_request(packets):
    return b''.join(packet.tcp.payload for packet in packets if packet.tcp.payload)

# Capture and handle packets using WinDivert
with pydivert.WinDivert("tcp.DstPort == 8000 or tcp.SrcPort == 8000") as w:
    logging.info("Listening on port 8000 and forwarding packets...")
    connections = {}

    for packet in w:
        conn_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
        
        if packet.tcp.syn and not packet.tcp.ack:
            # New connection setup
            logging.info(f"New connection setup from {packet.src_addr}:{packet.src_port} to {packet.dst_addr}:{packet.dst_port}")
            connections[conn_key] = []

        if packet.tcp.fin or packet.tcp.rst:
            # Connection teardown
            if conn_key in connections:
                logging.info(f"Connection teardown from {packet.src_addr}:{packet.src_port} to {packet.dst_addr}:{packet.dst_port}")
                del connections[conn_key]

        if packet.is_outbound and packet.tcp.payload:
            # Ensure the connection key exists in the dictionary
            if conn_key not in connections:
                connections[conn_key] = []
                
            # Extract the payload data
            connections[conn_key].append(packet)
            payload = reconstruct_http_request(connections[conn_key])
            logging.info(f"Outbound packet received with payload: {payload}")

            # Check if it is an OPTIONS request
            if b'OPTIONS' in payload:
                logging.info(f"Handling OPTIONS request: {payload}")
                response_packet = handle_options_request(packet)
                w.send(response_packet)
                continue

            # Forward the packet to the backend
            response = forward_packet(payload)

            if response:
                # Create a new packet to respond to the original packet
                response_packet = packet
                response_packet.tcp.payload = response
                logging.info(f"Response received from backend: {response}")
                w.send(response_packet)
            else:
                # Log and ignore the packet if forwarding fails
                logging.warning("Ignoring packet as forwarding failed")
        elif packet.is_inbound and packet.tcp.payload:
            # Log inbound responses
            logging.info(f"Inbound packet received with payload: {packet.tcp.payload}")
            w.send(packet)
        else:
            # Forward non-payload packets (e.g., SYN, ACK, FIN packets)
            w.send(packet)
            logging.info(f"Non-payload packet forwarded: {packet}")
