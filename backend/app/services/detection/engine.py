from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .rules_loader import Rule, load_rules
from .state_store import StateStore
from .alert_builder import build_alert


# -----------------------------
# utils
# -----------------------------

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
    if not rule.group_by:
        return "global"
    return "|".join(f"{f}={event.get(f)}" for f in rule.group_by)


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
    """
    核心匹配逻辑：
    - log_source 支持 str / list[str]
    - require 防空
    - match 等值
    - *_regex 正则
    """
    # 0) log_source
    ev_src = event.get("log_source")
    rule_src = rule.log_source

    if isinstance(rule_src, list):
        if ev_src not in rule_src:
            return False
    else:
        if ev_src != rule_src:
            return False

    # 1) require
    if not _has_required_fields(rule, event):
        return False

    # 2) match 等值
    for k, v in (rule.match or {}).items():
        if event.get(k) != v:
            return False

    # 3) *_regex
    for k, pattern in (rule.__dict__ or {}).items():
        if not k.endswith("_regex"):
            continue
        field = k[:-6]
        value = event.get(field)
        if value is None:
            return False
        try:
            if not re.search(pattern, str(value)):
                return False
        except re.error:
            return False

    return True


# -----------------------------
# Detection Engine
# -----------------------------

class DetectionEngine:
    def __init__(self, store: StateStore, rules_dir: str):
        self.store = store
        self.rules_dir = rules_dir
        self.rules: List[Rule] = []
        self.rule_meta: Dict[str, Dict[str, Any]] = {}

    def reload(self) -> None:
        self.rules = [r for r in load_rules(self.rules_dir) if r.enabled]

        for r in self.rules:
            print(
                "[RULE LOAD]",
                "id=", r.id,
                "require=", getattr(r, "require", None),
                "distinct_on=", getattr(r, "distinct_on", None),
                "group_by=", getattr(r, "group_by", None),
            )

        meta: Dict[str, Dict[str, Any]] = {}
        for r in self.rules:
            if not r.id:
                continue
            meta[r.id] = {
                "rule_id": r.id,
                "rule_title": r.title or r.name,
                "rule_desc": r.desc or "",
                "rule_why": r.why or "",
                "rule_advice": r.advice,
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
            print(
                "[RULE EVAL]",
                rule.id,
                "log_source=", rule.log_source,
                "event_source=", event.get("log_source"),
                "path=", event.get("path"),
                "distinct_on=", rule.distinct_on,
            )

            # ---------- sequence ----------
            if rule.sequence:
                a = self._eval_sequence(rule, event, ts)
                if a:
                    meta = self.rule_meta.get(rule.id)
                    if meta:
                        a.update(meta)
                    alerts.append(a)
                continue

            # ---------- normal window ----------
            if not _match(rule, event):
                continue

            gk = _group_key(rule, event)
            key_base = f"{rule.id}:{gk}"

            # ---------- distinct_on：用专用 distinct zset 计数 + 单独保存事件证据 ----------
            if rule.distinct_on:
                dv = "|".join(str(event.get(f, "")) for f in rule.distinct_on)

                # ✅ 1) distinct 计数：不受 keep_last 影响
                cnt = self.store.window_distinct_count(
                    key=key_base,
                    ts=ts,
                    window_sec=rule.window_sec,
                    distinct_value=dv,
                )

                # ✅ 2) 事件证据：单独 key 存，触发时可回填 events
                _, events = self.store.window_record_event(
                    key=f"{key_base}:evt",
                    ts=ts,
                    window_sec=rule.window_sec,
                    member=str(event.get("raw_id") or ts),
                    event_obj=self._compact_event(event),
                    keep_last=50,
                )

                reached = cnt >= rule.threshold
                extra = {
                    "distinct_count": cnt,
                    "window_sec": rule.window_sec,
                }

            # ---------- 普通窗口计数 ----------
            else:
                member = str(event.get("raw_id") or ts)
                cnt, events = self.store.window_record_event(
                    key=key_base,
                    ts=ts,
                    window_sec=rule.window_sec,
                    member=member,
                    event_obj=self._compact_event(event),
                    keep_last=50,
                )

                reached = cnt >= rule.threshold
                extra = {
                    "count": cnt,
                    "window_sec": rule.window_sec,
                }

            if not reached:
                continue

            # ---------- cooldown ----------
            dedup = _fmt_key(rule.dedup_key, rule.id, event)

            # ✅✅✅ 关键修复：cooldown_hit True=允许触发；False=冷却期禁止
            if not self.store.cooldown_hit(dedup, rule.cooldown_sec):
                continue

            # ---------- build alert ----------
            extra2 = dict(extra or {})
            extra2["events"] = events

            a = build_alert(rule, event, gk, extra2)

            meta = self.rule_meta.get(rule.id)
            if meta:
                a.update(meta)

            alerts.append(a)

        return alerts

    # -----------------------------
    # sequence
    # -----------------------------

    def _eval_sequence(
        self, rule: Rule, event: Dict[str, Any], ts: int
    ) -> Optional[Dict[str, Any]]:

        ev_src = event.get("log_source")
        rule_src = rule.log_source
        if isinstance(rule_src, list):
            if ev_src not in rule_src:
                return None
        else:
            if ev_src != rule_src:
                return None

        if not _has_required_fields(rule, event):
            return None

        seq = rule.sequence or {}
        fail_count = int(seq.get("fail_count", 5))
        fail_within = int(seq.get("fail_within_sec", 300))

        gk = _group_key(rule, event)
        key_base = f"{rule.id}:{gk}"

        outcome = event.get("outcome")

        if outcome == "fail":
            self.store.record_fail(key_base, ts, fail_within)
            return None

        if outcome == "success":
            if not self.store.had_recent_fail_burst(
                key_base, ts, fail_within, fail_count
            ):
                return None

            dedup = _fmt_key(rule.dedup_key, rule.id, event)
            if not self.store.cooldown_hit(dedup, rule.cooldown_sec):
                return None

            try:
                events = self.store.window_get_events(
                    f"{key_base}:fail", ts, fail_within, keep_last=50
                )
            except Exception:
                events = []

            extra = {
                "fail_count": fail_count,
                "fail_within_sec": fail_within,
                "events": events,
            }

            return build_alert(rule, event, gk, extra)

        return None

    # -----------------------------
    # compact event
    # -----------------------------

    @staticmethod
    def _compact_event(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": event.get("ts"),
            "attack_ip": event.get("src_ip"),
            "ip": event.get("src_ip"),
            "path": event.get("path"),
            "raw": event.get("raw"),
            "host": event.get("host"),
            "source": event.get("source"),
            "raw_id": event.get("raw_id"),
        }
