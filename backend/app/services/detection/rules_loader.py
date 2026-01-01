from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

import yaml


@dataclass
class Rule:
    id: str
    name: str
    enabled: bool
    log_source: str
    match: Dict[str, Any]
    group_by: List[str]
    window_sec: int
    threshold: int
    distinct_on: Optional[List[str]]
    cooldown_sec: int
    dedup_key: str
    severity: str
    tags: List[str]
    sequence: Optional[Dict[str, Any]]

    # 人类可读字段
    title: str = ""
    desc: str = ""
    why: str = ""
    advice: Optional[Union[str, List[str]]] = None
    require: List[str] = None


def _as_list(v: Any) -> Optional[List[str]]:
    if v is None:
        return None
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        s = v.strip()
        return [s] if s else []
    return [str(v)]


def _norm_rule(d: Dict[str, Any]) -> Rule:
    req = d.get("require", None)
    req_list = _as_list(req) or []

    return Rule(
        id=d["id"],
        name=d.get("name", d["id"]),
        enabled=bool(d.get("enabled", True)),
        log_source=d.get("log_source", "ssh"),
        match=d.get("match", {}) or {},
        group_by=d.get("group_by", []) or [],
        window_sec=int(d.get("window_sec", 60)),
        threshold=int(d.get("threshold", 1)),
        distinct_on=d.get("distinct_on"),
        cooldown_sec=int(d.get("cooldown_sec", 300)),
        dedup_key=d.get("dedup_key", "{rule_id}"),
        severity=str(d.get("severity", "MEDIUM")),
        tags=list(d.get("tags", []) or []),
        sequence=d.get("sequence"),

        title=str(d.get("title", "") or ""),
        desc=str(d.get("desc", "") or ""),
        why=str(d.get("why", "") or ""),
        advice=d.get("advice", None),
        require=req_list,
    )


def load_rules(rules_dir: str) -> List[Rule]:
    rules: List[Rule] = []

    if not os.path.isdir(rules_dir):
        return rules

    for fn in os.listdir(rules_dir):
        if not fn.endswith((".yml", ".yaml")):
            continue

        path = os.path.join(rules_dir, fn)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        rule = _norm_rule(data)
        rules.append(rule)

    rules.sort(key=lambda r: r.id)
    return rules
