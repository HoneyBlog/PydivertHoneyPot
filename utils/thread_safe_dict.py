import threading

class ThreadSafeDict:
    def __init__(self):
        self.lock = threading.Lock()
        self.dict = {}

    def set(self, key, value):
        with self.lock:
            self.dict[key] = value

    def get(self, key, default=None):
        with self.lock:
            return self.dict.get(key, default)

    def remove(self, key):
        with self.lock:
            if key in self.dict:
                del self.dict[key]
                