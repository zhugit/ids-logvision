from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .case import AttackCase


def fingerprint_hash(fp: Dict[str, Any]) -> str:
    s = json.dumps(fp or {}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


# 先做一个内存级关联（你后续要落库再改）
_HISTORY: Dict[str, List[str]] = {}  # fp_hash -> [case_id, ...]


def link_case(case: AttackCase) -> Dict[str, Any]:
    h = fingerprint_hash(case.fingerprints)
    chain = _HISTORY.get(h, [])
    chain.append(case.case_id)
    _HISTORY[h] = chain[-50:]  # 只保留最近 50 个
    return {"fingerprint_hash": h, "linked_case_ids": list(_HISTORY[h])}
