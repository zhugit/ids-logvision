from __future__ import annotations

from typing import Any, Dict, List, Optional

from .rules_loader import Rule, load_rules
from .state_store import StateStore
from .alert_builder import build_alert


def _fmt_key(template: str, rule_id: str, event: Dict[str, Any]) -> str:
    safe = {
        "rule_id": rule_id,
        "src_ip": event.get("src_ip", ""),
        "username": event.get("username", ""),
        "host": event.get("host", ""),
        "service": event.get("service", ""),
    }
    return template.format(**safe)


def _group_key(rule: Rule, event: Dict[str, Any]) -> str:
    parts = []
    for f in rule.group_by:
        parts.append(f"{f}={event.get(f)}")
    return "|".join(parts) if parts else "global"


def _has_required_fields(rule: Rule, event: Dict[str, Any]) -> bool:
    req = getattr(rule, "require", None) or []
    if not req:
        return True

    for f in req:
        v = event.get(f)
        if v is None:
            return False
        if isinstance(v, str) and v.strip() == "":
            return False
    return True


def _match(rule: Rule, event: Dict[str, Any]) -> bool:
    if event.get("log_source") != rule.log_source:
        return False

    # 误报兜底：必需字段校验
    if not _has_required_fields(rule, event):
        return False

    for k, v in (rule.match or {}).items():
        if event.get(k) != v:
            return False
    return True


class DetectionEngine:
    def __init__(self, store: StateStore, rules_dir: str):
        self.store = store
        self.rules_dir = rules_dir
        self.rules: List[Rule] = []
        # 人可读元信息
        self.rule_meta: Dict[str, Dict[str, Any]] = {}

    def reload(self) -> None:
        self.rules = [r for r in load_rules(self.rules_dir) if r.enabled]

        meta: Dict[str, Dict[str, Any]] = {}
        for r in self.rules:
            rid = getattr(r, "id", "") or ""
            if not rid:
                continue

            title = getattr(r, "title", "") or getattr(r, "name", "") or ""
            desc = getattr(r, "desc", "") or ""
            why = getattr(r, "why", "") or ""
            advice = getattr(r, "advice", None)

            if not title:
                title = f"{rid}（规则引擎）"

            meta[rid] = {
                "rule_id": rid,
                "rule_title": title,
                "rule_desc": desc,
                "rule_why": why,
                "rule_advice": advice,
            }

        self.rule_meta = meta

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.rules:
            self.reload()

        alerts: List[Dict[str, Any]] = []
        ts = int(event.get("ts") or 0)
        if ts <= 0:
            return alerts

        for rule in self.rules:
            # sequence rule
            if rule.sequence:
                a = self._eval_sequence(rule, event, ts)
                if a:
                    rid = getattr(rule, "id", "") or ""
                    meta = self.rule_meta.get(rid, {})
                    if meta:
                        a.update(meta)
                    alerts.append(a)
                continue

            # 普通窗口聚合
            if not _match(rule, event):
                continue

            gk = _group_key(rule, event)
            key_base = f"{rule.id}:{gk}"

            # distinct 逻辑（喷洒类）：这里只能给 distinct_count；events 仍可从普通窗口取“最近几条”
            if rule.distinct_on:
                dv = "|".join([str(event.get(f, "")) for f in rule.distinct_on])
                cnt = self.store.window_distinct_count(key_base, ts, rule.window_sec, dv)
                reached = cnt >= rule.threshold
                extra = {"distinct_count": cnt, "window_sec": rule.window_sec}

                # ✅ NEW：为了让前端有“多条证据”，也把普通事件写一份（不影响 distinct 计数）
                member = str(event.get("raw_id") or f"{ts}")
                _, events = self.store.window_record_event(
                    key=f"{key_base}:evt",
                    ts=ts,
                    window_sec=rule.window_sec,
                    member=member,
                    event_obj=self._compact_event(event),
                    keep_last=50,
                )

            else:
                member = str(event.get("raw_id") or f"{ts}")
                cnt, events = self.store.window_record_event(
                    key=key_base,
                    ts=ts,
                    window_sec=rule.window_sec,
                    member=member,
                    event_obj=self._compact_event(event),
                    keep_last=50,
                )
                reached = cnt >= rule.threshold
                extra = {"count": cnt, "window_sec": rule.window_sec}

            if not reached:
                continue

            dedup = _fmt_key(rule.dedup_key, rule.id, event)
            if not self.store.cooldown_hit(dedup, rule.cooldown_sec):
                continue

            a = build_alert(rule, event, gk, extra, events=events)

            rid = getattr(rule, "id", "") or ""
            meta = self.rule_meta.get(rid, {})
            if meta:
                a.update(meta)

            alerts.append(a)

        return alerts

    def _eval_sequence(self, rule: Rule, event: Dict[str, Any], ts: int) -> Optional[Dict[str, Any]]:
        if event.get("log_source") != rule.log_source:
            return None

        if not _has_required_fields(rule, event):
            return None

        seq = rule.sequence or {}
        fail_count = int(seq.get("fail_count", 5))
        fail_within = int(seq.get("fail_within_sec", 300))
        success_within = int(seq.get("success_within_sec", 60))

        gk = _group_key(rule, event)
        key_base = f"{rule.id}:{gk}"

        outcome = event.get("outcome")
        if outcome == "fail":
            self.store.record_fail(key_base, ts, fail_within)
            return None

        if outcome == "success":
            if not self.store.had_recent_fail_burst(key_base, ts, fail_within, fail_count):
                return None

            dedup = _fmt_key(rule.dedup_key, rule.id, event)
            if not self.store.cooldown_hit(dedup, rule.cooldown_sec):
                return None

            extra = {
                "fail_count": fail_count,
                "fail_within_sec": fail_within,
                "success_within_sec": success_within,
            }

            # ✅ NEW：sequence 也尽量给 events（取最近 fail_within 内的一些）
            # 这里不强依赖你是否提前记录事件：取不到就返回空列表也没关系
            try:
                events = self.store.window_get_events(key_base, ts, fail_within, keep_last=50)
            except Exception:
                events = []

            return build_alert(rule, event, gk, extra, events=events)

        return None

    @staticmethod
    def _compact_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        存入窗口 events 的“证据快照”，字段尽量对齐你前端表格：
          ts / attack_ip(ip) / user / port / raw / host / source / raw_id
        """
        return {
            "ts": event.get("ts"),
            "attack_ip": event.get("src_ip"),
            "ip": event.get("src_ip"),
            "user": event.get("username"),
            "port": event.get("port"),
            "raw": event.get("raw"),
            "host": event.get("host"),
            "source": event.get("source"),
            "raw_id": event.get("raw_id"),
        }
