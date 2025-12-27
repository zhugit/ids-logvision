import os
import json
import time
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

from ...stream import r  # 复用同一个 Redis 连接

load_dotenv()

WINDOW_SECONDS = int(os.getenv("SSH_BF_WINDOW_SECONDS", "60"))
THRESHOLD = int(os.getenv("SSH_BF_THRESHOLD", "5"))

# 用 Redis ZSET 存每个IP的失败时间戳（score=ts）
def _zkey(ip: str) -> str:
    return f"ids:sshbf:{ip}"

def record_failed(ip: str) -> int:
    now = int(time.time())
    key = _zkey(ip)

    # 加入当前失败事件
    r.zadd(key, {str(now): now})

    # 清理窗口外数据
    cutoff = now - WINDOW_SECONDS
    r.zremrangebyscore(key, 0, cutoff)

    # 统计窗口内数量
    cnt = r.zcard(key)

    # 设过期，避免垃圾键
    r.expire(key, WINDOW_SECONDS * 2)
    return int(cnt)

def should_alert(ip: str, count: int) -> bool:
    return count >= THRESHOLD

def build_alert_evidence(ip: str) -> str:
    # 取最近 N 条失败时间戳作为证据（简单够用）
    key = _zkey(ip)
    items = r.zrevrange(key, 0, THRESHOLD - 1, withscores=True)
    evidence = [{"ts": int(score)} for _, score in items]
    return json.dumps(evidence, ensure_ascii=False)

def severity_for_count(count: int) -> str:
    if count >= THRESHOLD + 10:
        return "HIGH"
    if count >= THRESHOLD + 5:
        return "MEDIUM"
    return "HIGH" if count >= THRESHOLD else "LOW"

def detect_ssh_bruteforce(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # parsed 需要包含 ip
    ip = parsed.get("ip")
    if not ip:
        return None

    cnt = record_failed(ip)
    if not should_alert(ip, cnt):
        return None

    return {
        "alert_type": "SSH_BRUTEFORCE",
        "attack_ip": ip,
        "count": cnt,
        "window_seconds": WINDOW_SECONDS,
        "severity": severity_for_count(cnt),
        "evidence": build_alert_evidence(ip),
    }
