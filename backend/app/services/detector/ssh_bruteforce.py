import os
import json
import time
import uuid
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

from ...stream import r  # 复用同一个 Redis 连接

load_dotenv()

WINDOW_SECONDS = int(os.getenv("SSH_BF_WINDOW_SECONDS", "60"))
THRESHOLD = int(os.getenv("SSH_BF_THRESHOLD", "5"))

# ZSET: 每个 IP 一个 key，score=ts(ms)，member=uuid
# HASH: 每个 member -> 事件详情（json 字符串）
# 这样既能按时间窗口统计，又能把“原始日志/用户/端口/主机”等证据保留下来

def _zkey(ip: str) -> str:
    return f"ids:sshbf:{ip}"

def _hkey(ip: str) -> str:
    return f"ids:sshbf:ev:{ip}"

def _now_ms() -> int:
    return int(time.time() * 1000)

def _expire_seconds() -> int:
    return WINDOW_SECONDS * 2

def record_failed(ip: str, event: Dict[str, Any]) -> int:
    """
    记录一次失败事件：
    - ZSET 用于统计窗口内数量（score=ts）
    - HASH 存 member -> event json
    """
    ts = _now_ms()
    z = _zkey(ip)
    h = _hkey(ip)

    ev_id = event.get("id") or uuid.uuid4().hex[:8]
    event = dict(event)
    event["id"] = ev_id
    event["ts"] = ts  # 毫秒，便于前端/展示

    # 写入
    r.zadd(z, {ev_id: ts})
    r.hset(h, ev_id, json.dumps(event, ensure_ascii=False))

    # 清理窗口外：ZSET 删除 + HASH 同步删除
    cutoff = ts - (WINDOW_SECONDS * 1000)
    old_ids = r.zrangebyscore(z, 0, cutoff)
    if old_ids:
        # zset 删
        r.zremrangebyscore(z, 0, cutoff)
        # hash 删
        # old_ids 是 bytes list，转 str
        old_ids_str = [x.decode() if isinstance(x, (bytes, bytearray)) else str(x) for x in old_ids]
        if old_ids_str:
            r.hdel(h, *old_ids_str)

    # 统计窗口内数量
    cnt = r.zcard(z)

    # 过期
    r.expire(z, _expire_seconds())
    r.expire(h, _expire_seconds())
    return int(cnt)

def should_alert(count: int) -> bool:
    return count >= THRESHOLD

def severity_for_count(count: int) -> str:
    # 你也可以后面按需要细化
    if count >= THRESHOLD + 10:
        return "HIGH"
    if count >= THRESHOLD + 5:
        return "MEDIUM"
    return "HIGH" if count >= THRESHOLD else "LOW"

def _format_cn_summary(ip: str, host: str, port: str, user: str, count: int) -> str:
    # 一眼看懂的中文摘要（前端直接展示）
    # host 你目前只有 hostname，没有 dst_ip，就先这样
    return (
        f"【SSH 口令爆破】来源 IP：{ip} → 目标主机：{host}:{port}，"
        f"尝试用户：{user}，{WINDOW_SECONDS} 秒内失败 {count} 次"
    )

def _recommendations_cn(ip: str) -> List[str]:
    # 规则级处置建议（现在就能用，后面 AI 替换/增强）
    return [
        f"建议临时封禁攻击 IP：{ip}（防火墙 / 安全组 / fail2ban）",
        "检查是否存在弱口令账户（如 root / admin / test 等），必要时强制改密",
        "建议关闭 SSH 密码登录，启用密钥认证（PasswordAuthentication no）",
        "限制 22 端口访问来源（仅允许运维出口 IP），或改为非默认端口并配合 MFA/VPN",
        "查看同时间段其他主机是否出现相同来源 IP 的横向尝试"
    ]

def build_alert_evidence(ip: str, fallback: Dict[str, Any], count: int) -> str:
    """
    evidence 统一输出为：
    {
      "schema": "evidence.v1",
      "summary_cn": "...",
      "recommendations_cn": [...],
      "events": [ {ts, attack_ip, host, user, port, source, raw, id}, ... ],
      "ai_analysis": { enabled:false, status:"not_analyzed", ... }   # 预留
    }

    兼容历史：如果 hash 查不到（比如老版本只存 ts），就退化为 ts 列表。
    """
    z = _zkey(ip)
    h = _hkey(ip)

    # 取最近 THRESHOLD 条（或按 count 取，避免阈值变动）
    take_n = max(THRESHOLD, min(count, THRESHOLD))
    ids = r.zrevrange(z, 0, take_n - 1)
    ids = [x.decode() if isinstance(x, (bytes, bytearray)) else str(x) for x in ids]

    events: List[Dict[str, Any]] = []
    if ids:
        raw_map = r.hmget(h, ids)
        for ev_id, ev_json in zip(ids, raw_map):
            if not ev_json:
                continue
            try:
                if isinstance(ev_json, (bytes, bytearray)):
                    ev_json = ev_json.decode()
                ev = json.loads(ev_json)
                # 补齐一些字段，避免前端空
                ev.setdefault("id", ev_id)
                ev.setdefault("attack_ip", ip)
                events.append(ev)
            except Exception:
                continue

    # 如果 events 空（比如老数据），就 fallback 成 ts-only 的结构
    if not events:
        # 旧版只存 ts 的兼容结构
        ts_items = r.zrevrange(z, 0, take_n - 1, withscores=True)
        ts_only = [{"ts": int(score)} for _, score in ts_items]
        evidence_obj = {
            "schema": "evidence.v1",
            "summary_cn": _format_cn_summary(
                ip=ip,
                host=str(fallback.get("host") or ""),
                port=str(fallback.get("port") or "22"),
                user=str(fallback.get("user") or "-"),
                count=count,
            ),
            "recommendations_cn": _recommendations_cn(ip),
            "events": ts_only,
            "ai_analysis": {
                "enabled": False,
                "status": "not_analyzed",
                "risk_score": None,
                "false_positive": None,
                "suggestion_cn": None,
            },
        }
        return json.dumps(evidence_obj, ensure_ascii=False)

    # 从 events 里抽摘要关键字段（尽量取最新一条）
    latest = events[0]
    host = str(latest.get("host") or fallback.get("host") or "")
    port = str(latest.get("port") or fallback.get("port") or "22")
    user = str(latest.get("user") or fallback.get("user") or "-")

    evidence_obj = {
        "schema": "evidence.v1",
        "summary_cn": _format_cn_summary(ip=ip, host=host, port=port, user=user, count=count),
        "recommendations_cn": _recommendations_cn(ip),
        "events": events,
        "ai_analysis": {
            "enabled": False,
            "status": "not_analyzed",
            "risk_score": None,
            "false_positive": None,
            "suggestion_cn": None,
        },
    }
    return json.dumps(evidence_obj, ensure_ascii=False)

def detect_ssh_bruteforce(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    输入 parsed（来自 parse_ssh_failed）：
    需要包含 ip；建议包含 host/source/user/port/raw
    """
    ip = parsed.get("ip") or parsed.get("attack_ip")
    if not ip:
        return None

    # 事件细节尽可能保留：raw/message/用户/端口/主机等
    event = {
        "attack_ip": ip,
        "host": str(parsed.get("host") or ""),
        "user": str(parsed.get("user") or "-"),
        "port": str(parsed.get("port") or "22"),
        "source": str(parsed.get("source") or "ssh"),
        # raw：优先用 parsed 里带的 raw；没有就用 message（你 main 里是 message 字段）
        "raw": str(parsed.get("raw") or parsed.get("message") or ""),
    }

    cnt = record_failed(ip, event)
    if not should_alert(cnt):
        return None

    sev = severity_for_count(cnt)
    evidence = build_alert_evidence(ip, fallback=event, count=cnt)

    return {
        "alert_type": "SSH_BRUTEFORCE",
        "attack_ip": ip,
        "count": cnt,
        "window_seconds": WINDOW_SECONDS,
        "severity": sev,
        "evidence": evidence,
    }
