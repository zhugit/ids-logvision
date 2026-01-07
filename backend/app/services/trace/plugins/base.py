from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..case import TraceStep


@dataclass
class MatchResult:
    ok: bool
    score: float = 0.0
    reasons: List[str] = None

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []


class TracePlugin:
    """
    溯源插件基类：只负责“解释这批事件像不像某类攻击 + 生成时间线/指纹/阶段链”
    """

    name: str = "base"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        raise NotImplementedError

    def build_timeline(self, rawlogs: List[Any]) -> List[TraceStep]:
        return []

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return []

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        return {}

    # -------- helpers --------

    @staticmethod
    def g(obj: Any, *keys: str, default=None):
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None and str(v).strip() != "":
                return v
        return default

    @staticmethod
    def s(obj: Any, *keys: str) -> str:
        v = TracePlugin.g(obj, *keys, default="")
        return str(v).strip() if v is not None else ""

    @staticmethod
    def i(obj: Any, *keys: str) -> Optional[int]:
        v = TracePlugin.g(obj, *keys, default=None)
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            return None
