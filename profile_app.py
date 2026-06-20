
import time
import requests
import sys

BASE_URL = "http://127.0.0.1:5000"
ENDPOINTS = [
    "/",
    "/history",
    "/monitor",
    "/dynamic_analysis",
    "/api/monitor/stats",
    "/api/monitor/events"
]

def profile():
    print(f"{'Endpoint':<25} | {'Response Time (s)':<20} | {'Status'}")
    print("-" * 60)
    
    for endpoint in ENDPOINTS:
        try:
            start_time = time.time()
            response = requests.get(BASE_URL + endpoint, timeout=30)
            duration = time.time() - start_time
            print(f"{endpoint:<25} | {duration:<20.4f} | {response.status_code}")
        except Exception as e:
            print(f"{endpoint:<25} | {'FAILED':<20} | {str(e)}")

if __name__ == "__main__":
    profile()
