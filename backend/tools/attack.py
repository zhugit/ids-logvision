# backend/tools/attack.py
import argparse
import time
import uuid
import requests
from datetime import datetime

API_DEFAULT = "http://localhost:8000"

def build_samples(ip: str, n: int):
    users = [
        "root", "admin", "test", "ubuntu", "oracle", "postgres", "mysql",
        "www-data", "git", "user", "dev", "backup"
    ]
    lines = []
    for i in range(n):
        u = users[i % len(users)]
        lines.append(f"Failed password for invalid user {u} from {ip} port 22 ssh2")
    return lines

def post_ingest(api: str, payload: dict, timeout: int = 10):
    r = requests.post(f"{api}/ingest", json=payload, timeout=timeout)
    return r.status_code, r.text

def get_alerts(api: str, timeout: int = 10):
    r = requests.get(f"{api}/alerts", timeout=timeout)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text

def main():
    p = argparse.ArgumentParser(description="LogVision ingest+alert E2E test (with unique tag)")
    p.add_argument("--api", default=API_DEFAULT, help="API base url, default http://localhost:8000")
    p.add_argument("--source", default="ssh", help="raw_logs.source")
    p.add_argument("--host", default="server1", help="raw_logs.host")
    p.add_argument("--level", default="WARN", help="raw_logs.level")
    p.add_argument("--ip", default="192.168.1.10", help="attacker ip in log line")
    p.add_argument("--n", type=int, default=8, help="number of failed attempts to send")
    p.add_argument("--sleep", type=float, default=0.05, help="sleep seconds between each log")
    p.add_argument("--wait", type=float, default=1.0, help="wait seconds for detector after sending")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    args = p.parse_args()

    api = args.api.rstrip("/")

    # ✅ 唯一标记：确保你能在 DB 里 LIKE 一下就找到
    tag = f"ZMQTEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    print(f"[TAG] {tag}")

    samples = build_samples(args.ip, args.n)

    print("\n[1] send logs to /ingest ...")
    ok = 0
    for i, line in enumerate(samples, 1):
        payload = {
            "source": args.source,
            "host": args.host,
            "level": args.level,
            "message": f"{line} [{tag}]",  # ✅ 关键：message + tag
        }
        code, text = post_ingest(api, payload, timeout=args.timeout)
        print(f"  ingest {i}: {code} {text[:160]}")
        if 200 <= code < 300:
            ok += 1
        time.sleep(args.sleep)

    if ok == 0:
        print("\n[!] 全部 ingest 失败：说明你后端 /ingest 的必填字段还没对齐。")
        print("    当前发送 body = {source, host, level, message}")
        print("    你看 422 里缺哪个字段，就把 payload 里加上。")
        return

    print(f"\n[2] sent ok: {ok}/{len(samples)}. wait detector {args.wait}s ...")
    time.sleep(args.wait)

    print("\n[3] fetch /alerts ...")
    code, data = get_alerts(api, timeout=args.timeout)
    print("  /alerts status:", code)

    if isinstance(data, list):
        print("  /alerts returns list, len =", len(data))
        if data:
            newest = data[0]
            print("  newest alert summary:")
            for k in ["id", "alert_type", "severity", "attack_ip", "host", "count", "window_seconds", "created_at"]:
                if k in newest:
                    print(f"    {k}: {newest.get(k)}")
        else:
            print("  (empty list) 当前 alerts 没有记录/没有新增")
    elif isinstance(data, dict):
        # 兼容未来你把 /alerts 改成 dict 结构
        items = data.get("items") or []
        print("  /alerts returns dict, items len =", len(items))
        if items:
            print("  newest alert:", items[0])
    else:
        print("  /alerts response:", data)

    print("\n[4] verify in Navicat (copy & run) ...")
    print("  --- Find inserted raw_logs by TAG ---")
    print(f"  SELECT id, source, host, level, message, created_at")
    print(f"  FROM raw_logs")
    print(f"  WHERE message LIKE '%{tag}%'")
    print(f"  ORDER BY id DESC;")
    print("\n  --- Latest 5 raw_logs ---")
    print("  SELECT id, source, host, level, message, created_at FROM raw_logs ORDER BY id DESC LIMIT 5;")
    print("\n  --- Latest 5 alerts ---")
    print("  SELECT id, alert_type, severity, attack_ip, host, count, created_at FROM alerts ORDER BY id DESC LIMIT 5;")

if __name__ == "__main__":
    main()
