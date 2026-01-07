from __future__ import annotations

from typing import Any, Dict, List
import re

from .base import MatchResult, TracePlugin
from ..case import TraceStep


class DeserializationTracePlugin(TracePlugin):
    name = "deserialization"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        reasons = []
        score = 0.0

        for r in rawlogs:
            ctype = self.s(r, "content_type", "ctype")
            body_size = self.i(r, "body_size", "req_size")
            err = self.s(r, "error", "exception", "stack")

            # 常见的“二进制/序列化”内容类型或异常关键词（只用于识别）
            if ctype and ("octet-stream" in ctype.lower() or "serialized" in ctype.lower()):
                score += 1.0
                reasons.append("请求内容类型呈现二进制/序列化特征")

            if body_size is not None and body_size > 2000 and (ctype and "octet-stream" in ctype.lower()):
                score += 0.6
                reasons.append("请求体较大且为二进制类型（疑似序列化数据提交）")

            if err and re.search(r"(deserialize|unserialize|invalid stream|classnotfound)", err, re.I):
                score += 1.1
                reasons.append("应用日志出现反序列化相关异常特征")

        ok = score >= 1.2
        return MatchResult(ok=ok, score=min(score, 5.0), reasons=_dedup(reasons))

    def build_timeline(self, rawlogs: List[Any]) -> List[TraceStep]:
        steps: List[TraceStep] = []
        for r in rawlogs:
            ts = self.g(r, "created_at", "ts", "time", "timestamp")
            if ts is None:
                continue
            steps.append(
                TraceStep(
                    ts=ts,
                    action="二进制数据提交/反序列化尝试",
                    detail={
                        "path": self.s(r, "path", "uri", "url_path"),
                        "content_type": self.s(r, "content_type", "ctype"),
                        "status": self.i(r, "status", "code"),
                    },
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["探测", "反序列化提交", "异常/回显观察"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        endpoints = []
        ctypes = []
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
            c = self.s(r, "content_type", "ctype")
            if c:
                ctypes.append(c.lower())
        return {"kind": "Deserialization", "endpoints_top": _topk(endpoints, 3), "content_types": _topk(ctypes, 3)}


def _topk(items: List[str], k: int) -> List[str]:
    from collections import Counter
    return [x for x, _ in Counter([i for i in items if i]).most_common(k)]


def _dedup(xs: List[str]) -> List[str]:
    out = []
    seen = set()
    for x in xs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out
