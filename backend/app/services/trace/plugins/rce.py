from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import MatchResult, TracePlugin
from ..case import TraceStep


_RCE_SEPARATORS = [
    r"(\;|\|\||\&\&|\||`)",
    r"\$\(",     # $(...)
]


class RCETracePlugin(TracePlugin):
    name = "rce"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        reasons = []
        score = 0.0

        for r in rawlogs:
            path = self.s(r, "path", "uri", "url_path")
            query = self.s(r, "query", "qs")
            body = self.s(r, "body", "request_body")
            status = self.i(r, "status", "code")

            blob = f"{path}?{query} {body}"

            hit = 0
            for pat in _RCE_SEPARATORS:
                if re.search(pat, blob):
                    hit += 1
            if hit >= 1:
                score += 1.1
                reasons.append("检测到疑似命令注入/执行分隔符特征（可疑连接符/子命令结构）")

            if status in (500, 502, 503):
                score += 0.2
                reasons.append("出现服务端异常响应（可能与执行失败/异常有关）")

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
                    action="可疑执行尝试（疑似 RCE/命令注入链路）",
                    detail={
                        "path": self.s(r, "path", "uri", "url_path"),
                        "status": self.i(r, "status", "code"),
                    },
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["探测", "执行尝试", "回显/异常观察"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        endpoints = []
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
        return {"kind": "RCE", "endpoints_top": _topk(endpoints, 3)}


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
