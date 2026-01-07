from __future__ import annotations

from typing import Any, Dict, List

from .base import MatchResult, TracePlugin
from ..case import TraceStep


class GenericTracePlugin(TracePlugin):
    """
    永远可用的兜底溯源插件：把 normalize 过的字段做成“可回放时间线”。
    """
    name = "generic"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        # 永远可匹配，但分数最低，只有没别的插件命中才会选它
        return MatchResult(ok=True, score=0.1, reasons=["基础回放（兜底插件）"])

    def build_timeline(self, rawlogs: List[Any]) -> List[TraceStep]:
        steps: List[TraceStep] = []
        for r in rawlogs:
            ts = self.g(r, "created_at")
            if ts is None:
                continue

            proto = (self.s(r, "protocol") or "unknown").lower()
            if proto == "http":
                action = "HTTP 请求"
                detail = {
                    "method": self.s(r, "method"),
                    "path": self.s(r, "path"),
                    "query": self.s(r, "query"),
                    "status": self.i(r, "status"),
                    "ua": self.s(r, "ua"),
                }
            elif proto == "ssh":
                action = "SSH 认证行为"
                detail = {
                    "ssh_action": self.s(r, "ssh_action"),
                    "ssh_user": self.s(r, "ssh_user"),
                    "port": self.i(r, "ssh_port"),
                }
            else:
                action = "原始日志事件"
                detail = {"message": self.s(r, "message")[:200]}

            steps.append(TraceStep(ts=ts, action=action, detail=detail, ref_raw_id=self.i(r, "id")))
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["观测", "回放"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        # 最小指纹：协议 + top path
        paths = []
        proto = ""
        for r in rawlogs:
            if not proto and r.get("protocol"):
                proto = r["protocol"]
            p = r.get("path")
            if p:
                paths.append(p)
        top_path = paths[0] if paths else ""
        return {"kind": "Generic", "protocol": proto, "top_path": top_path}
