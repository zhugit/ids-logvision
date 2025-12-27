import time
import requests

API = "http://localhost:8000/ingest"

# 你可以在这里换成你自己的失败日志样本
SAMPLES = [
    "Failed password for invalid user root from 192.168.1.10 port 22 ssh2",
    "Failed password for invalid user admin from 192.168.1.10 port 22 ssh2",
    "Failed password for invalid user test from 192.168.1.10 port 22 ssh2",
    "Failed password for invalid user ubuntu from 192.168.1.10 port 22 ssh2",
    "Failed password for invalid user oracle from 192.168.1.10 port 22 ssh2",
]

def post_with_retry(payload: dict, retries: int = 3, timeout: int = 30):
    last_err = None
    for i in range(retries):
        try:
            r = requests.post(API, json=payload, timeout=timeout)
            return r.status_code, r.text
        except requests.exceptions.RequestException as e:
            last_err = e
            time.sleep(0.5 * (i + 1))
    raise last_err

if __name__ == "__main__":
    for idx, msg in enumerate(SAMPLES, 1):
        payload = {
            "source": "replay",
            "host": "server2",
            "level": "WARN",
            "message": msg,
        }
        code, text = post_with_retry(payload, retries=3, timeout=30)
        print(idx, code, text)
        time.sleep(0.2)
