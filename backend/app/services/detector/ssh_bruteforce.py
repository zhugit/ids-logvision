import os
import json
import time
import uuid
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from ...stream import r  # 复用同一个 Redis 连接

load_dotenv()

WINDOW_SECONDS = int(os.getenv("SSH_BF_WINDOW_SECONDS", "60"))
THRESHOLD = int(os.getenv("SSH_BF_THRESHOLD", "5"))

def _zkey(host: str, ip: str) -> str:
    host = host or "unknown"
    return f"ids:sshbf:{host}:{ip}"

def _make_event(parsed: Dict[str, Any], host: str, ip: str, ts_ms: int) -> str:
    ev = {
        "ts": ts_ms,
        "attack_ip": ip,
        "host": host,
        "user": parsed.get("user", ""),
        "port": parsed.get("port", ""),
        "source": parsed.get("source", ""),
        "raw": parsed.get("raw") or parsed.get("message") or "",
        "id": uuid.uuid4().hex[:8],
    }
    return json.dumps(ev, ensure_ascii=False)

def record_failed(parsed: Dict[str, Any], host: str, ip: str) -> int:
    now_ms = int(time.time() * 1000)
    key = _zkey(host, ip)

    member = _make_event(parsed, host, ip, now_ms)
    r.zadd(key, {member: now_ms})

    cutoff_ms = now_ms - WINDOW_SECONDS * 1000
    r.zremrangebyscore(key, 0, cutoff_ms)

    cnt = r.zcard(key)
    r.expire(key, WINDOW_SECONDS * 2)
    return int(cnt)

def should_alert(count: int) -> bool:
    return count >= THRESHOLD

def build_alert_evidence(host: str, ip: str) -> str:
    """
    ✅ 兼容旧数据：过滤掉 raw 为空的旧事件，直到凑够 THRESHOLD 条。
    为了避免无限取，我们最多取 100 条来筛选。
    """
    key = _zkey(host, ip)
    items = r.zrevrange(key, 0, 100)  # 多取一点，过滤旧数据

    evidence: list[dict] = []
    for raw in items:
        try:
            ev = json.loads(raw)
        except Exception:
            continue

        # ✅ 过滤旧格式/缺字段
        if not isinstance(ev, dict):
            continue
        if not ev.get("raw"):
            continue

        evidence.append(ev)
        if len(evidence) >= THRESHOLD:
            break

    # 如果过滤后还不够（极端情况），就退化：把原始 items 也塞进来，保证不为空
    if len(evidence) < THRESHOLD:
        for raw in items:
            try:
                ev = json.loads(raw)
                if isinstance(ev, dict):
                    evidence.append(ev)
                else:
                    evidence.append({"raw": str(raw)})
            except Exception:
                evidence.append({"raw": str(raw)})
            if len(evidence) >= THRESHOLD:
                break

    return json.dumps(evidence[:THRESHOLD], ensure_ascii=False)

def severity_for_count(count: int) -> str:
    if count >= THRESHOLD + 10:
        return "HIGH"
    if count >= THRESHOLD + 5:
        return "MEDIUM"
    return "HIGH"

def detect_ssh_bruteforce(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ip = parsed.get("ip") or parsed.get("attack_ip")
    host = parsed.get("host") or "unknown"
    if not ip:
        return None

    cnt = record_failed(parsed, host, ip)
    if not should_alert(cnt):
        return None

    return {
        "alert_type": "SSH_BRUTEFORCE",
        "attack_ip": ip,
        "count": cnt,
        "window_seconds": WINDOW_SECONDS,
        "severity": severity_for_count(cnt),
        "evidence": build_alert_evidence(host, ip),
    }
