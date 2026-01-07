from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import MatchResult, TracePlugin
from ..case import TraceStep


_SQLI_HINTS = [
    # 只做识别，不提供利用方法
    r"\bunion\b",
    r"\bselect\b",
    r"\border\b\s+\bby\b",
    r"\bfrom\b",
    r"\band\b|\bor\b",
    r"(--|#|/\*)",
    r"(\%27|')",  # 单引号/URL编码引号
]


class SQLiTracePlugin(TracePlugin):
    name = "sqli"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        reasons = []
        score = 0.0

        for r in rawlogs:
            path = self.s(r, "path", "uri", "url_path")
            query = self.s(r, "query", "qs")
            body = self.s(r, "body", "request_body")
            status = self.i(r, "status", "code")

            blob = f"{path}?{query} {body}".lower()

            hit = 0
            for pat in _SQLI_HINTS:
                if re.search(pat, blob, re.I):
                    hit += 1

            if hit >= 2:
                score += 1.2
                reasons.append("检测到疑似 SQL 注入探测特征（参数/语句片段/注释符号）")
            if status in (500, 502, 503):
                score += 0.3
                reasons.append("出现服务端异常响应（可能与 SQL 错误/异常有关）")

        ok = score >= 1.5
        return MatchResult(ok=ok, score=min(score, 5.0), reasons=_dedup(reasons))

    def build_timeline(self, rawlogs: List[Any]) -> List[TraceStep]:
        steps: List[TraceStep] = []
        for r in rawlogs:
            ts = self.g(r, "created_at", "ts", "time", "timestamp")
            if ts is None:
                continue

            path = self.s(r, "path", "uri", "url_path")
            status = self.i(r, "status", "code")
            rt = self.g(r, "response_time", "rt", default=None)

            detail = {"path": path, "status": status}
            if rt is not None:
                detail["response_time"] = rt

            steps.append(
                TraceStep(
                    ts=ts,
                    action="参数探测/异常回显（疑似 SQL 注入链路）",
                    detail=detail,
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["探测", "注入尝试", "回显/异常观察"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        # endpoint + 参数名集合（如果 query 字段可取到）
        endpoints = []
        param_names = set()
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
            qs = self.s(r, "query", "qs")
            for n in re.findall(r"([a-zA-Z0-9_\-]+)=", qs):
                param_names.add(n.lower())

        return {
            "kind": "SQLi",
            "endpoints_top": _topk(endpoints, 3),
            "param_names": sorted(list(param_names))[:30],
        }


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
