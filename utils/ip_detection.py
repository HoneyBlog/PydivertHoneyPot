import logging

class IPDetection:
    def __init__(self, ip_list):
        self.ip_list = "../files/" + ip_list
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    def is_in_list(self, ip):
        try:
            with open(self.ip_list, 'r') as file:
                for line in file:
                    if ip in line.strip():
                        logging.info(f"IP {ip} found in {self.ip_list}")
                        return True
            logging.info(f"IP {ip} not found in {self.ip_list}")
            return False
        except FileNotFoundError:
            logging.error(f"The file {self.ip_list} does not exist.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while checking if IP {ip} is in {self.ip_list}: {e}")

    def add_ip_to_list(self, ip):
        try:
            with open(self.ip_list, mode='a') as file:
                file.write(ip + '\n')
            logging.info(f"Added {ip} to {self.ip_list}")
        except FileNotFoundError:
            logging.error(f"The file {self.ip_list} does not exist.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while adding IP {ip} to {self.ip_list}: {e}")

    def remove_ip_from_list(self, ip):
        try:
            with open(self.ip_list, 'r') as file:
                lines = file.readlines()
            with open(self.ip_list, 'w') as file:
                for line in lines:
                    if line.strip("\n") != ip:
                        file.write(line)
            logging.info(f"Removed {ip} from {self.ip_list}")
        except FileNotFoundError:
            logging.error(f"The file {self.ip_list} does not exist.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while removing IP {ip} from {self.ip_list}: {e}")

# Example usage:
# detector = IPDetection('ip_list.txt')
# detector.is_in_list('192.168.0.1')
# detector.add_ip_to_list('192.168.0.1')
# detector.remove_ip_from_list('192.168.0.1')
