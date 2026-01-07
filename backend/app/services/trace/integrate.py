from __future__ import annotations

import json
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.models import Alert
from app.services.trace.builder import build_attack_case
from app.services.trace.engine import run_trace
from app.services.trace.linker import link_case


def integrate_trace_into_alert(db: Session, alert_row: Alert) -> Dict[str, Any]:
    """
    在 Alert 已经入库后调用：
    - 回溯 raw_logs 生成 AttackCase
    - 跑溯源插件得到 timeline / fingerprints / tactic_chain
    - 把结果写回 alert_row.evidence（JSON字符串）
    返回写入的 trace dict，方便你日志打印/调试。
    """
    case = build_attack_case(db, alert_row, window_seconds=alert_row.window_seconds or 60)
    case = run_trace(case)
    link = link_case(case)

    # 原 evidence 可能已经是 JSON（你目前 evidence 字段存的是 JSON 字符串）
    old_obj: Dict[str, Any] = {}
    if alert_row.evidence:
        try:
            old_obj = json.loads(alert_row.evidence)
            if not isinstance(old_obj, dict):
                old_obj = {"evidence": old_obj}
        except Exception:
            old_obj = {"evidence_text": alert_row.evidence}

    trace_obj = {
        "case": case.to_dict(),
        "link": link,
    }

    # 合并：保留你原来的 evidence/events/assessment/human_summary_cn 等
    merged = dict(old_obj)
    merged["trace"] = trace_obj

    alert_row.evidence = json.dumps(merged, ensure_ascii=False)

    # ✅ 关键：让更新立刻写进当前事务，后续 publish/query 能读到新 evidence
    db.add(alert_row)
    db.flush()

    # 注意：不 commit，让调用方决定事务
    return trace_obj
