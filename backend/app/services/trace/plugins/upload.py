from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from collections import defaultdict

from .base import MatchResult, TracePlugin
from ..case import TraceStep


_ID_KEYS = ("id", "userId", "uid", "orderId", "couponId", "accountId", "resourceId")


class LogicBugTracePlugin(TracePlugin):
    name = "logic_bug"

    def match(self, rawlogs: List[Any]) -> MatchResult:
        """
        逻辑漏洞靠“身份/会话一致，但资源 ID 变化 + 返回正常”来判。
        """
        reasons = []
        score = 0.0

        # 以 session/token/user 为主键聚合，查看是否出现“资源切换”
        buckets = defaultdict(list)
        for r in rawlogs:
            sid = self.s(r, "session_id", "sid")
            uid = self.s(r, "user_id", "uid", "account_id")
            tok = self.s(r, "token_hash", "token")
            key = sid or tok or uid
            if key:
                buckets[key].append(r)

        for key, items in buckets.items():
            res_ids = set()
            ok200 = 0
            for r in items:
                status = self.i(r, "status", "code")
                if status == 200:
                    ok200 += 1
                rid = _extract_resource_id(r)
                if rid:
                    res_ids.add(rid)

            if len(res_ids) >= 3 and ok200 >= 2:
                score += 1.6
                reasons.append("同一会话/身份下出现多资源 ID 访问且返回正常（疑似越权/业务绕过）")

        ok = score >= 1.6
        return MatchResult(ok=ok, score=min(score, 5.0), reasons=_dedup(reasons))

    def build_timeline(self, rawlogs: List[Any]) -> List[TraceStep]:
        steps: List[TraceStep] = []
        for r in rawlogs:
            ts = self.g(r, "created_at", "ts", "time", "timestamp")
            if ts is None:
                continue
            rid = _extract_resource_id(r)
            steps.append(
                TraceStep(
                    ts=ts,
                    action="业务资源访问/可能的越权链路",
                    detail={
                        "path": self.s(r, "path", "uri", "url_path"),
                        "resource_id": rid,
                        "status": self.i(r, "status", "code"),
                        "user_id": self.s(r, "user_id", "uid", "account_id"),
                        "session_id": self.s(r, "session_id", "sid"),
                    },
                    ref_raw_id=self.i(r, "id"),
                )
            )
        return steps

    def infer_tactic_chain(self, rawlogs: List[Any]) -> List[str]:
        return ["身份/会话建立", "资源枚举/切换", "业务绕过尝试"]

    def extract_fingerprint(self, rawlogs: List[Any]) -> Dict[str, Any]:
        endpoints = []
        rid_keys = set()
        for r in rawlogs:
            p = self.s(r, "path", "uri", "url_path")
            if p:
                endpoints.append(p)
            qs = self.s(r, "query", "qs")
            for k in _ID_KEYS:
                if f"{k}=" in qs:
                    rid_keys.add(k)
        return {"kind": "LogicBug", "endpoints_top": _topk(endpoints, 3), "resource_id_keys": sorted(list(rid_keys))}


def _extract_resource_id(r: Any) -> str:
    qs = TracePlugin.s(r, "query", "qs")
    for k in _ID_KEYS:
        m = re.search(rf"(?:^|[?&]){re.escape(k)}=([0-9]+)", qs)
        if m:
            return f"{k}:{m.group(1)}"
    # 也尝试从 path 里抠 /user/123 /order/456
    path = TracePlugin.s(r, "path", "uri", "url_path")
    m2 = re.search(r"/(user|users|order|orders|account|coupon)s?/(?:detail/)?(\d+)", path, re.I)
    if m2:
        return f"{m2.group(1).lower()}:{m2.group(2)}"
    return ""


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
