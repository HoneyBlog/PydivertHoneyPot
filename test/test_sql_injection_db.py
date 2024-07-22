import sys
import os
import psycopg2
from dotenv import load_dotenv

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load environment variables from .env file
load_dotenv()

# Get database connection details from environment variables
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# Test payloads for potential SQL injection
test_payloads = [
    "SELECT * FROM users WHERE username = 'admin' AND password = 'password';",
    "SELECT username, password FROM users UNION SELECT 'a', 'b';",
    "SELECT * FROM users WHERE username = '' OR '1'='1';",
    "SELECT * FROM users WHERE username = '' OR 1=1 --;",
    "SELECT * FROM users WHERE username = '' OR 'a'='a';",
    "SELECT * FROM users WHERE username = '' OR ''='';",
]

def test_sql_injection_on_db(payloads):
    vulnerabilities_found = False  # Flag to track if any vulnerabilities are found
    safe_queries_count = 0  # Counter for safe queries
    try:
        # Connect to the PostgreSQL database
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cur = conn.cursor()
        
        for payload in payloads:
            try:
                cur.execute(payload)  # Execute the query
                result = cur.fetchall()
                if result:  # If there are results, it indicates potential vulnerability
                    vulnerabilities_found = True
                    print(f"Payload executed successfully: {payload}")
                    for row in result:
                        print(row)
                else:
                    safe_queries_count += 1
            except psycopg2.Error as e:
                conn.rollback()
                print(f"Failed to execute payload: {payload}")
                print(f"Error: {e}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Failed to connect to the database: {e}")
    
    # Summary message
    if vulnerabilities_found:
        print("SQL injection vulnerabilities found in the database.")
    else:
        print(f"No SQL injection vulnerabilities found in the database. {safe_queries_count}/{len(test_payloads)} queries were safe.")

# Test payloads on the database
test_sql_injection_on_db(test_payloads)
