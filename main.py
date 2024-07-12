import logging
import pydivert
import re

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def reconstruct_http_request(packets):
    """
    Reconstructs an HTTP request from a list of packets.
    """
    req = b''.join(packet.tcp.payload for packet in packets if packet.tcp.payload)
    logging.info(f"Reconstructed HTTP request: {req}")
    return req

def is_complete_http_request(payload):
    """
    Checks if the payload contains a complete HTTP request.
    """
    if b'\r\n\r\n' in payload:
        headers, body = payload.split(b'\r\n\r\n', 1)
        # Use regular expression to find the Content-Length value
        match = re.search(b'content-length:\s*(\d+)', headers.lower())
        if match:
            content_length = int(match.group(1))
            return len(body) >= content_length
        return True
    return False

def main():
    """
    Main function to capture and process packets.
    """
    # Define the filter for capturing TCP packets on port 8000
    filter = "tcp.DstPort == 8000 or tcp.SrcPort == 8000"
    with pydivert.WinDivert(filter) as w:
        logging.info("Listening on port 8000 and forwarding packets...")
        for packet in w:
            if packet.is_outbound:
                logging.info("Outbound packet captured.")
            else:
                logging.info("Inbound packet captured.")
            
            # Attempt to reconstruct the HTTP request from packets
            http_request = reconstruct_http_request([packet])
            
            # Check if the HTTP request is complete
            if is_complete_http_request(http_request):
                logging.info("Complete HTTP request received.")
            else:
                logging.info("Incomplete HTTP request received.")
            
            # Forward the packet
            w.send(packet)

if __name__ == "__main__":
    main()