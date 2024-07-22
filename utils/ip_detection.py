from utils.logger_config import CustomLogger
logger = CustomLogger().get_logger()

class IPDetection:
    def __init__(self, ip_list):
        self.file_name=ip_list
        self.ip_list = "./files/" + ip_list
    
    def is_in_list(self, ip):
        try:
            with open(self.ip_list, 'r') as file:
                for line in file:
                    if ip in line.strip():
                        logger.info(f"IP {ip} found in {self.file_name}")
                        return True
            logger.info(f"IP {ip} not found in {self.file_name}")
            return False
        except FileNotFoundError:
            logger.error(f"The file {self.file_name} does not exist.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while checking if IP {ip} is in {self.file_name}: {e}")

    def add_ip_to_list(self, ip):
        try:
            with open(self.file_name, mode='a') as file:
                file.write(ip + '\n')
            logger.info(f"Added {ip} to {self.file_name}")
        except FileNotFoundError:
            logger.error(f"The file {self.file_name} does not exist.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while adding IP {ip} to {self.file_name}: {e}")

    def remove_ip_from_list(self, ip):
        try:
            with open(self.ip_list, 'r') as file:
                lines = file.readlines()
            with open(self.ip_list, 'w') as file:
                for line in lines:
                    if line.strip("\n") != ip:
                        file.write(line)
            logger.info(f"Removed {ip} from {self.file_name}")
        except FileNotFoundError:
            logger.error(f"The file {self.file_name} does not exist.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while removing IP {ip} from {self.file_name}: {e}")

