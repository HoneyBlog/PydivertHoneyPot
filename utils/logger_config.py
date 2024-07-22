import logging

class CustomLogger:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(CustomLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self, name='CustomLogger', log_file='./files/logs.txt', level=logging.INFO):
        # Ensure initialization happens only once
        if hasattr(self, '_initialized') and self._initialized:
            return

        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Check if the logger already has handlers to avoid adding them multiple times
        if not self.logger.hasHandlers():
            # Create console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)

            # Create file handler
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setLevel(level)

            # Create formatter and add it to handlers
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)

            # Add handlers to the logger
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

        self._initialized = True

    def get_logger(self):
        return self.logger
