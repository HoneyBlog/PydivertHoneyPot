import sys
import os
import re

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Attacks.Sql_Injection import check_sql_injection

# Test payloads
test_payloads = [
    "SELECT * FROM users WHERE username = 'admin' AND password = 'password';",
    "UNION SELECT username, password FROM users;",
    "INSERT INTO users (username, password) VALUES ('admin', 'password');",
    "UPDATE users SET password = 'newpassword' WHERE username = 'admin';",
    "DELETE FROM users WHERE username = 'admin';",
    "DROP TABLE users;",
    "ALTER TABLE users ADD COLUMN email VARCHAR(255);",
    "CREATE TABLE test (id INT);",
    "-- This is a comment",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "' OR ''='",
    "\" OR \"\"=\"",
]

# Run tests
for payload in test_payloads:
    result = check_sql_injection(payload)
    print(f"Payload: {payload}")
    print(f"Injection Detected: {result}\n")
