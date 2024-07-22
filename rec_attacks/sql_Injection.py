import re
import logging

# Path to the file containing the list of blocked IPs
blocked_file = "./files/blacklist_sql.txt"

def check_sql_injection(payload):
    # Convert bytes-like object to string if necessary
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='ignore')

    # List of common SQL injection patterns
    sql_patterns = [
        r"(?i)select.*from.*",     # SELECT ... FROM ...
        r"(?i)union.*select.*",    # UNION SELECT ...
        r"(?i)insert.*into.*",     # INSERT INTO ...
        r"(?i)update.*set.*",      # UPDATE ... SET ...
        r"(?i)delete.*from.*",     # DELETE FROM ...
        r"(?i)drop.*table.*",      # DROP TABLE ...
        r"(?i)alter.*table.*",     # ALTER TABLE ...
        r"(?i)create.*table.*",    # CREATE TABLE ...
        r"(?i)--",                 # SQL comment
        r"(?i)' or '1'='1",        # Simple tautology
        r"(?i)\" or \"1\"=\"1",    # Simple tautology
        r"(?i)' OR 1=1 --",        # Simple tautology
        r"(?i)\" OR 1=1 --",       # Simple tautology
        r"(?i)' OR 'a'='a",        # Simple tautology
        r"(?i)\" OR \"a\"=\"a",    # Simple tautology
        r"(?i)' OR ''='",          # Simple tautology
        r"(?i)\" OR \"\"=\"",      # Simple tautology
    ]

    for pattern in sql_patterns:
        if re.search(pattern, payload):
            print(f"SQL pattern matched: {pattern}")
            return True
    return False

def is_blacklisted_sql(ip):
    try:
        with open(blocked_file, 'r') as file:
            for line in file:
                if ip in line.strip():
                    return True
        return False
    except Exception as e:
        logging.error(f"An error occurred while checking if IP {ip} is blocked: {e}")

def add_ip_to_blacklist_file(ip):
    with open(blocked_file, mode='a') as file:
        # check if the IP is already in the file
        if is_blacklisted_sql(ip):
            logging.info(f"IP {ip} is already in the blacklist")
            return
        file.write(ip + '\n')
    logging.info(f"Added {ip} to blacklist")