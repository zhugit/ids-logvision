from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TraceStep:
    ts: datetime
    action: str  # 中文动作
    detail: Dict[str, Any] = field(default_factory=dict)
    ref_raw_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # datetime 序列化给前端
        d["ts"] = self.ts.isoformat()
        return d


@dataclass
class AttackCase:
    case_id: str
    trigger_rule: str
    trigger_ts: datetime

    # 攻击来源/目标（尽量填，填不到也不影响）
    src_ip: str = ""
    protocol: str = ""
    dst_host: str = ""
    dst_port: Optional[int] = None
    dst_path: str = ""

    # 原始证据（RawLog 实体列表 or dict）
    rawlogs: List[Any] = field(default_factory=list)

    # 溯源输出
    timeline: List[TraceStep] = field(default_factory=list)
    tactic_chain: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    infrastructure: Dict[str, Any] = field(default_factory=dict)

    # 解释型信息
    plugin: str = ""            # 命中的溯源插件
    plugin_score: float = 0.0   # 命中分
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "trigger_rule": self.trigger_rule,
            "trigger_ts": self.trigger_ts.isoformat(),
            "src_ip": self.src_ip,
            "protocol": self.protocol,
            "dst_host": self.dst_host,
            "dst_port": self.dst_port,
            "dst_path": self.dst_path,
            "plugin": self.plugin,
            "plugin_score": self.plugin_score,
            "reasons": self.reasons,
            "tactic_chain": self.tactic_chain,
            "fingerprints": self.fingerprints,
            "infrastructure": self.infrastructure,
            "timeline": [s.to_dict() for s in self.timeline],
            # rawlogs 不直接全吐，避免太大；你需要可以改成只返回 id 列表
            "evidence_rawlog_ids": [_safe_get(r, "id") for r in self.rawlogs],
        }


def _safe_get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
