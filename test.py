import socket
import logging

logging.basicConfig(level=logging.INFO)

def test_socket_connection():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            logging.info("Attempting to connect to honeypot server on 127.0.0.1:8001")
            s.connect(("127.0.0.1", 8001))
            logging.info("Connected to honeypot server")
            
            test_payload = "Test payload"
            s.sendall(test_payload.encode('utf-8'))
            logging.info("Test payload sent successfully")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Failed to connect to honeypot server: {e}")

if __name__ == "__main__":
    test_socket_connection()
