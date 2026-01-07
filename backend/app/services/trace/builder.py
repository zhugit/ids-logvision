from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select

from app.models import RawLog, Alert
from .case import AttackCase


# -----------------------------
# Regex: Nginx/Apache access-like
# -----------------------------
# 兼容常见格式：
# 1.2.3.4 - - [date] "GET /path?x=1 HTTP/1.1" 200 123 "-" "UA"
_ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
    r'(?P<uri>\S+)\s+HTTP/(?P<httpver>[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)")?(?:\s+"(?P<ua>[^"]*)")?',
    re.IGNORECASE
)

# -----------------------------
# Regex: SSH failed password
# Failed password for invalid user root from 1.2.3.4 port 22 ssh2
# Failed password for root from 1.2.3.4 port 22 ssh2
# -----------------------------
_SSH_FAIL_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)',
    re.IGNORECASE
)

# SSH accepted
_SSH_OK_RE = re.compile(
    r'Accepted \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)',
    re.IGNORECASE
)

# URL param keys often for SSRF
_SSRF_PARAM_KEYS = ("url=", "target=", "dest=", "redirect=", "callback=", "next=")


def build_attack_case(db, alert: Alert, window_seconds: Optional[int] = None, limit: int = 1500) -> AttackCase:
    """
    以 Alert 为触发点回溯 RawLog，并做 normalize（从 message 解析 HTTP/SSH 字段）。
    """
    trigger_ts = alert.created_at or datetime.utcnow()
    win = int(window_seconds if window_seconds is not None else (alert.window_seconds or 60))

    t0 = trigger_ts - timedelta(seconds=win)
    t1 = trigger_ts + timedelta(seconds=win)

    src_ip = (alert.attack_ip or "").strip()
    trigger_rule = (alert.alert_type or "UNKNOWN").strip()

    # 查 raw_logs：你的 RawLog 没有 src_ip 字段，只能从 message LIKE 过滤 + 时间过滤
    stmt = select(RawLog).where(
        and_(
            RawLog.created_at >= t0,
            RawLog.created_at <= t1,
        )
    ).order_by(RawLog.created_at.asc()).limit(limit)

    raw_rows = list(db.execute(stmt).scalars().all())

    # 用 src_ip 再做一次 message 层过滤（更准）
    if src_ip:
        raw_rows = [r for r in raw_rows if src_ip in (r.message or "")]

    norm_logs: List[Dict[str, Any]] = [normalize_rawlog(r) for r in raw_rows]

    # AttackCase
    case = AttackCase(
        case_id=f"case-{uuid.uuid4().hex[:12]}",
        trigger_rule=trigger_rule,
        trigger_ts=trigger_ts,
        src_ip=src_ip,
        protocol="",      # 由 normalize 填
        dst_host=alert.host or "",
        dst_port=None,
        dst_path="",
        rawlogs=norm_logs,  # ✅ 注意：这里传的是 dict 列表
    )

    # 尝试从 evidence(JSON) 里补充信息（不强依赖）
    _fill_from_alert_evidence(case, alert.evidence)

    # 尝试从 normalize 结果中补充：protocol/host/path/port
    _fill_target_from_norm(case)

    # 基础设施画像（能拿多少拿多少）
    case.infrastructure = {
        "src_ip": src_ip,
        "host": alert.host or "",
        "alert_type": trigger_rule,
        "severity": getattr(alert, "severity", "") or "",
        "count": getattr(alert, "count", 0) or 0,
        "window_seconds": win,
        "user_agent": _first(case.rawlogs, "ua") or _first(case.rawlogs, "user_agent") or "",
    }

    return case


def build_attack_case_by_alert_id(db, alert_id: int, window_seconds: Optional[int] = None) -> AttackCase:
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one()
    return build_attack_case(db, alert, window_seconds=window_seconds)


# -----------------------------
# normalize: RawLog -> dict
# -----------------------------
def normalize_rawlog(r: RawLog) -> Dict[str, Any]:
    msg = (r.message or "").strip()

    d: Dict[str, Any] = {
        "id": r.id,
        "created_at": r.created_at,
        "source": r.source,
        "host": r.host,
        "level": r.level,
        "message": msg,

        # 下面这些是“解析出来的结构化字段”（插件用）
        "protocol": "",     # http / ssh / unknown
        "src_ip": "",
        "method": "",
        "path": "",
        "query": "",
        "status": None,
        "bytes": None,
        "ua": "",
        "referer": "",
        "ssh_user": "",
        "ssh_port": None,
        "ssh_action": "",   # fail / success
    }

    # 1) HTTP access
    m = _ACCESS_RE.search(msg)
    if m:
        ip = m.group("ip") or ""
        method = (m.group("method") or "").upper()
        uri = m.group("uri") or ""
        status = int(m.group("status")) if (m.group("status") and m.group("status").isdigit()) else None
        bytes_ = m.group("bytes")
        bytes_v = int(bytes_) if bytes_ and bytes_.isdigit() else None
        ua = m.group("ua") or ""
        referer = m.group("referer") or ""

        path, qs = _split_uri(uri)

        d.update({
            "protocol": "http",
            "src_ip": ip,
            "method": method,
            "path": path,
            "query": qs,
            "status": status,
            "bytes": bytes_v,
            "ua": ua,
            "referer": referer,
        })
        return d

    # 2) SSH fail / success
    m2 = _SSH_FAIL_RE.search(msg)
    if m2:
        d.update({
            "protocol": "ssh",
            "src_ip": m2.group("ip") or "",
            "ssh_user": m2.group("user") or "",
            "ssh_port": int(m2.group("port")) if m2.group("port") else None,
            "ssh_action": "fail",
        })
        return d

    m3 = _SSH_OK_RE.search(msg)
    if m3:
        d.update({
            "protocol": "ssh",
            "src_ip": m3.group("ip") or "",
            "ssh_user": m3.group("user") or "",
            "ssh_port": int(m3.group("port")) if m3.group("port") else None,
            "ssh_action": "success",
        })
        return d

    # 3) fallback：只要能抠出 IP 也行
    ip = _extract_ip(msg)
    if ip:
        d["src_ip"] = ip

    return d


def _split_uri(uri: str) -> (str, str):
    if "?" not in uri:
        return uri, ""
    path, qs = uri.split("?", 1)
    return path, qs


def _extract_ip(s: str) -> str:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
    return m.group(1) if m else ""


def _fill_from_alert_evidence(case: AttackCase, evidence_text: str) -> None:
    if not evidence_text:
        return
    try:
        obj = json.loads(evidence_text)
        # evidence 里如果有 url/path/host 之类字段，补上（兼容你不同证据结构）
        if isinstance(obj, dict):
            case.dst_host = case.dst_host or str(obj.get("host", "")).strip()
            case.dst_path = case.dst_path or str(obj.get("path", "")).strip()
    except Exception:
        return


def _fill_target_from_norm(case: AttackCase) -> None:
    # 从第一条 http/ssh 记录补 protocol/port/path
    for r in case.rawlogs:
        proto = (r.get("protocol") or "").strip()
        if not case.protocol and proto:
            case.protocol = proto

        if proto == "ssh" and case.dst_port is None:
            p = r.get("ssh_port")
            if isinstance(p, int):
                case.dst_port = p

        if proto == "http" and not case.dst_path:
            case.dst_path = r.get("path") or ""

        if case.protocol and (case.dst_port is not None or case.dst_path):
            break


def _first(items: List[Dict[str, Any]], key: str) -> str:
    for it in items:
        v = it.get(key)
        if v:
            return str(v)
    return ""
