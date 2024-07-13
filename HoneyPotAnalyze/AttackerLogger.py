import csv
from datetime import datetime
import geoip2.database

class AttackerLogger:
    def __init__(self, log_file='hp_analysis.csv'):
        self.log_file = log_file

    def get_geo_location(self, ip_address):
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.city(ip_address)
                country = response.country.name
                city = response.city.name
                return f"{city}, {country}"
        except Exception as e:
            return "Location Unknown"
        
    def log_attacker_info(self, ip, port, intention, payload):
        geo_location = self.get_geo_location(ip)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = [timestamp, ip, port, geo_location, intention, payload]

        with open(self.log_file, "a", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(log_entry)
