from __future__ import annotations

from typing import List

from .case import AttackCase
from .plugins.base import TracePlugin

from .plugins.sqli import SQLiTracePlugin
from .plugins.rce import RCETracePlugin
from .plugins.deserialization import DeserializationTracePlugin
from .plugins.logic_bug import LogicBugTracePlugin
#from .plugins.upload import UploadTracePlugin
from .plugins.ssrf import SSRFTracePlugin
from .plugins.xss import XSSTracePlugin
from .plugins.generic import GenericTracePlugin


DEFAULT_PLUGINS: List[TracePlugin] = [
    SQLiTracePlugin(),
    RCETracePlugin(),
    DeserializationTracePlugin(),
    LogicBugTracePlugin(),
    #UploadTracePlugin(),
    SSRFTracePlugin(),
    XSSTracePlugin(),
    GenericTracePlugin(),  # ✅ 兜底放最后
]


def run_trace(case: AttackCase, plugins: List[TracePlugin] = None) -> AttackCase:
    plugins = plugins or DEFAULT_PLUGINS

    best_plugin = None
    best_mr = None

    for p in plugins:
        mr = p.match(case.rawlogs)
        if not mr.ok:
            continue
        if best_mr is None or mr.score > best_mr.score:
            best_plugin, best_mr = p, mr

    # 理论上不会空，因为 Generic 永远 ok
    if best_plugin is None:
        case.plugin = "unknown"
        case.reasons = ["未匹配到任何溯源插件"]
        return case

    case.plugin = best_plugin.name
    case.plugin_score = best_mr.score
    case.reasons = best_mr.reasons

    case.timeline = best_plugin.build_timeline(case.rawlogs)
    case.tactic_chain = best_plugin.infer_tactic_chain(case.rawlogs)
    case.fingerprints = best_plugin.extract_fingerprint(case.rawlogs)

    return case
