import re

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