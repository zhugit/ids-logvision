import requests
import time

API = "http://localhost:8000/ingest"

paths = [
    "/admin",
    "/login",
    "/phpinfo.php",
    "/.git/config",
    "/wp-login.php",
    "/backup.zip",
    "/test",
    "/api/admin",
]

for i, p in enumerate(paths, 1):
    payload = {
        "source": "nginx",
        "host": "web-01",
        "level": "WARN",
        "message": f'1.2.3.4 - - [01/Jan/2026:12:00:01 +0800] "GET {p} HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
    }
    r = requests.post(API, json=payload)
    print(f"[{i}] send {p} -> {r.status_code}")
    time.sleep(0.3)
