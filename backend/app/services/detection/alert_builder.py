from __future__ import annotations
from typing import Any, Dict

def _human_summary_cn(rule: Any, event: Dict[str, Any], group_key: str, extra: Dict[str, Any] | None) -> str:
    rule_name = getattr(rule, "name", "") or getattr(rule, "id", "规则告警")
    src_ip = event.get("src_ip") or "-"
    host = event.get("host") or "-"
    user = event.get("username") or "-"
    port = event.get("port") or "-"
    window = None
    count = None

    if extra:
        window = extra.get("window_sec") or extra.get("window_seconds")
        count = extra.get("count")
        if count is None:
            count = extra.get("distinct_count")

    # 兜底：窗口、次数没有就不写死
    if window and count is not None:
        return f"【{rule_name}】{src_ip} 在 {window} 秒内对 {host}:{port} 失败 {count} 次（账号 {user}）。"
    if count is not None:
        return f"【{rule_name}】{src_ip} 对 {host}:{port} 失败 {count} 次（账号 {user}）。"
    return f"【{rule_name}】{src_ip} 对 {host}:{port} 出现异常登录行为（账号 {user}）。"

def build_alert(rule: Any, event: Dict[str, Any], group_key: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "tags": rule.tags,
        "log_source": rule.log_source,
        "group_key": group_key,
        "src_ip": event.get("src_ip"),
        "username": event.get("username"),
        "ts": event.get("ts"),
        "raw_id": event.get("raw_id"),
    }

    if extra:
        payload.update(extra)

    # ✅ NEW：一眼看懂的人话描述（给前端直接用）
    payload["human_summary_cn"] = _human_summary_cn(rule, event, group_key, extra)

    # 你原来的 summary 留着（不影响）
    payload["summary"] = f"{rule.name} | {group_key}"

    # ✅ 也把端口带进来，前端更好展示（不会破坏旧逻辑）
    if "port" not in payload:
        payload["port"] = event.get("port")

    return payload
