import requests

url = "http://127.0.0.1:8000/api/users/login/"
payload = {"username": "eido321", "password": "QQaazz11"}
headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
