from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import MatchResult, TracePlugin
from ..case import TraceStep


_URL_PARAM_KEYS = ("url", "target", "dest", "redirect", "callback", "next")


class SSRFTracePlugin(TracePlugin):
    name = "ssrf"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        reasons = []
        score = 0.0

        for r in rawlogs:
            qs = self.s(r, "query", "qs")
            path = self.s(r, "path", "uri", "url_path")

            # 有 url 类参数
            if any(f"{k}=" in qs for k in _URL_PARAM_KEYS):
                score += 0.8
                reasons.append("请求参数包含 URL/跳转类字段（疑似 SSRF/回调入口）")

            # 参数值像 URL
            if re.search(r"(http|https)%3a%2f%2f|https?://", qs, re.I):
                score += 0.9
                reasons.append("参数值呈现外部 URL 结构（疑似 SSRF 目标指定）")

        ok = score >= 1.5
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
                    action="外部资源请求/内网探测入口（疑似 SSRF）",
                    detail={
                        "path": self.s(r, "path", "uri", "url_path"),
                        "status": self.i(r, "status", "code"),
                    },
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["入口探测", "目标指定", "连通性/回显观察"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        endpoints = []
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
        return {"kind": "SSRF", "endpoints_top": _topk(endpoints, 3)}


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
