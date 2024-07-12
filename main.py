# TO DO: check in wire shark why the honeypot server is not receiving the packets

import logging
import pydivert
import re
from Attacks.Sql_Injection import check_sql_injection

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """
    Main function to capture and process packets.
    """
    # Define the filter for capturing TCP packets on port 8000
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
                        packet.dst_addr = "127.0.0.1"
                        packet.dst_port = 8001 
                        logging.info("Packet destination address and port changed to honeypot server - %s:%d" % (packet.dst_addr, packet.dst_port))

                w.send(packet)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Stopped packet capture.")

if __name__ == "__main__":
    main()
