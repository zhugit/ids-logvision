from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import MatchResult, TracePlugin
from ..case import TraceStep


class XSSTracePlugin(TracePlugin):
    name = "xss"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        reasons = []
        score = 0.0

        for r in rawlogs:
            qs = self.s(r, "query", "qs")
            body = self.s(r, "body", "request_body")

            blob = (qs + " " + body).lower()

            # 只做“是否包含脚本/事件型结构”的识别，不给利用payload
            if "<" in blob and ">" in blob:
                score += 0.6
                reasons.append("参数/请求体包含 HTML 结构符号")
            if "script" in blob:
                score += 0.8
                reasons.append("出现脚本关键字（疑似 XSS 探测）")
            if re.search(r"on[a-z]+\s*=", blob):
                score += 0.7
                reasons.append("出现事件处理器结构（疑似 XSS 探测）")

        ok = score >= 1.6
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
                    action="输入点探测/反射观察（疑似 XSS）",
                    detail={
                        "path": self.s(r, "path", "uri", "url_path"),
                        "status": self.i(r, "status", "code"),
                    },
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["输入点探测", "反射/存储验证", "触发尝试（若存在）"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        endpoints = []
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
        return {"kind": "XSS", "endpoints_top": _topk(endpoints, 3)}


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
