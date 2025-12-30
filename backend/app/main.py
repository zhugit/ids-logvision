from datetime import datetime, timezone, timedelta
import asyncio
from typing import Optional, Any, List, Dict

from fastapi import FastAPI, Depends, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select, and_
from starlette.websockets import WebSocketDisconnect

from .db import engine, Base, get_db
from .models import RawLog, Alert
from .schemas import IngestLogIn, AlertOut, RawLogOut
from .stream import (
    RAWLOG_STREAM_KEY,
    ALERT_STREAM_KEY,
    publish_rawlog,
    publish_alert,
    stream_xread,
    get_redis,
    redis_info,
    stream_lengths,
    ensure_streams,
)

from .services.parser.ssh import parse_ssh_failed
from .services.detector.ssh_bruteforce import detect_ssh_bruteforce

# ✅✅✅ DEBUG：确认当前运行时加载的 parse_ssh_failed 到底来自哪个文件（只定位，不影响功能）
import inspect
print("[DEBUG] parse_ssh_failed from:", inspect.getfile(parse_ssh_failed))

# -----------------------------
# ✅ NEW: Rule Engine imports
# -----------------------------
import os
import time
import json

from .services.detection.engine import DetectionEngine
from .services.detection.state_store import StateStore

app = FastAPI(
    title="LogVision IDS API",
    version="0.3.0",
    description=(
        "Real-time Log IDS: ingest -> parse -> detect -> alert -> WebSocket.\n"
        "REST APIs provide ingestion and history queries; WebSocket streams provide real-time logs and alerts."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ 中国时区（UTC+8）
CHINA_TZ = timezone(timedelta(hours=8))


def now_cn() -> datetime:
    return datetime.now(CHINA_TZ)


def fmt_cn(dt: Optional[datetime]) -> str:
    """统一输出中国时间字符串，前端直接展示，不再解析时区。"""
    if not dt:
        return ""
    # dt 可能是 naive（MySQL DATETIME 读出来通常是 naive）
    # 这里按“它就是中国时间”来格式化展示
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def safe_evidence(v: Any) -> Any:
    """
    防止 dict/list 直接写入 DB 导致：
    sqlalchemy.exc.ProgrammingError: dict can not be used as parameter
    """
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


# -----------------------------
# ✅ NEW: Detection Engine (Rule-as-Code)
# -----------------------------
RULES_DIR = os.path.join(os.path.dirname(__file__), "services", "detection", "rules")

_det_store = StateStore(get_redis(), prefix="det")
det_engine = DetectionEngine(_det_store, rules_dir=RULES_DIR)

try:
    det_engine.reload()
    print(f"[DETECTION] Loaded rules from: {RULES_DIR}, count={len(det_engine.rules)}")
except Exception as e:
    print("[DETECTION] Failed to load rules:", repr(e))


# -----------------------------
# ✅ NEW: Build standardized event for rule engine
# -----------------------------
def build_event_from_ssh_failed(parsed: dict, row: Any) -> dict:
    """
    parser(parse_ssh_failed) 输出字段：
      - user/ip/attack_ip/port/event/raw
    rule engine 需要字段：
      - log_source/ts/src_ip/username/outcome/host/raw_id/port/raw
    """
    raw = parsed.get("raw") or getattr(row, "message", "") or ""

    # ✅ 端口：优先用 parsed.port；没有就从 raw 里提取 “port 22”
    port = parsed.get("port")
    if port in (None, "", 0):
        try:
            import re
            m = re.search(r"\bport\s+(\d+)\b", str(raw))
            port = int(m.group(1)) if m else None
        except Exception:
            port = None

    return {
        "log_source": "ssh",
        "ts": int(time.time()),
        "src_ip": parsed.get("ip") or parsed.get("attack_ip") or "",
        "username": parsed.get("user") or "",
        "outcome": "fail",
        "host": getattr(row, "host", None),
        "source": getattr(row, "source", None),
        "raw_id": getattr(row, "id", None),
        "port": port,     # ✅ NEW
        "raw": raw,
    }

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    try:
        ensure_streams()
    except Exception:
        pass


@app.get("/health", tags=["System"], summary="Health check")
def health():
    # ✅ 健康检查也返回中国时间，避免你调试时混淆
    return {"ok": True, "time": now_cn().strftime("%Y-%m-%d %H:%M:%S")}


# -----------------------------
# ✅ Debug: 你浏览器访问 /debug/redis 不再 404
# -----------------------------
@app.get("/debug/redis", tags=["System"], summary="Redis debug info")
def debug_redis():
    return {
        "redis": redis_info(),
        "streams": stream_lengths(),
        "ensure": ensure_streams(),
    }


# -----------------------------
# Docs
# -----------------------------
@app.get(
    "/docs/ws",
    tags=["Docs"],
    summary="WebSocket protocol documentation",
    description="Human-friendly documentation for WebSocket message types used by this service.",
)
def ws_docs():
    return {
        "ws_logs": {
            "url": "/ws/logs",
            "description": (
                "Real-time raw logs stream.\n"
                "- The server starts reading from the latest Redis Stream ID at connect time (no DB replay).\n"
                "- On idle, server sends {type: ping}.\n"
                "- On Redis errors, server sends {type: status, data: {...}}.\n"
            ),
            "start_position": "latest_stream_id",
            "message_types": {
                "log": {
                    "schema": {
                        "type": "log",
                        "data": {
                            "id": "string",
                            "source": "string",
                            "host": "string",
                            "level": "string",
                            "message": "string",
                            "created_at": "string(China time, YYYY-MM-DD HH:MM:SS)",
                        },
                    },
                    "example": {
                        "type": "log",
                        "data": {
                            "id": "123",
                            "source": "auth.log",
                            "host": "srv-01",
                            "level": "INFO",
                            "message": "Failed password for invalid user root from 192.168.1.10 port 22 ssh2",
                            "created_at": "2025-12-29 20:00:00",
                        },
                    },
                },
                "ping": {
                    "schema": {"type": "ping"},
                    "example": {"type": "ping"},
                },
                "status": {
                    "schema": {"type": "status", "data": {"redis": "down", "stream": "rawlog"}},
                    "example": {"type": "status", "data": {"redis": "down", "stream": "rawlog"}},
                },
            },
        },
        "ws_alerts": {
            "url": "/ws/alerts",
            "description": (
                "Real-time alerts stream.\n"
                "- The server starts reading from the latest Redis Stream ID at connect time (no DB replay).\n"
                "- On idle, server sends {type: ping}.\n"
                "- On Redis errors, server sends {type: status, data: {...}}.\n"
            ),
            "start_position": "latest_stream_id",
            "message_types": {
                "alert": {
                    "schema": {
                        "type": "alert",
                        "data": {
                            "id": "string",
                            "alert_type": "string",
                            "severity": "string",
                            "attack_ip": "string",
                            "host": "string",
                            "count": "string(int)",
                            "window_seconds": "string(int)",
                            "evidence": "any",
                            "created_at": "string(China time, YYYY-MM-DD HH:MM:SS)",
                        },
                    },
                    "example": {
                        "type": "alert",
                        "data": {
                            "id": "9",
                            "alert_type": "SSH_BRUTE_FORCE",
                            "severity": "HIGH",
                            "attack_ip": "192.168.1.10",
                            "host": "srv-01",
                            "count": "6",
                            "window_seconds": "60",
                            "evidence": {"users": ["root", "admin"], "fail_count": 6},
                            "created_at": "2025-12-29 20:01:30",
                        },
                    },
                },
                "ping": {
                    "schema": {"type": "ping"},
                    "example": {"type": "ping"},
                },
                "status": {
                    "schema": {"type": "status", "data": {"redis": "down", "stream": "alert"}},
                    "example": {"type": "status", "data": {"redis": "down", "stream": "alert"}},
                },
            },
        },
        "openapi": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json",
        },
    }


# -----------------------------
# Ingest
# -----------------------------
@app.post(
    "/ingest",
    tags=["Ingest"],
    summary="Ingest one raw log line",
    description=(
        "Write one raw log into database, publish it to Redis Stream, then run parser+detector.\n"
        "If detector triggers, create an alert row and publish alert to Redis Stream.\n"
        "Use ?debug=true to get parsed and detection details for troubleshooting."
    ),
)
def ingest(
    payload: IngestLogIn,
    db: Session = Depends(get_db),
    debug: bool = Query(False, description="调试模式：返回 parsed/alert_data，便于定位为何不出告警"),
):
    # ✅ 不手动传 created_at，让 models.py 的 default（中国时间）生效
    row = RawLog(
        source=payload.source,
        host=payload.host,
        level=payload.level,
        message=payload.message,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # 推送实时日志到 Redis Stream（失败不影响主流程）
    try:
        publish_rawlog(
            {
                "id": str(row.id),
                "source": row.source,
                "host": row.host,
                "level": row.level,
                "message": row.message,
                "created_at": fmt_cn(getattr(row, "created_at", None)),
            }
        )
    except Exception:
        pass

    # -----------------------------
    # ✅ 解析 + 检测（关键定位点）
    # -----------------------------
    msg = row.message or ""
    needle = "Failed password"
    idx = msg.find(needle)
    norm_msg = msg[idx:] if idx >= 0 else msg  # 兼容前缀带 TAG 的情况

    parsed = None
    alert_data = None
    detector_error = None

    # ✅ 两套检测开关：默认都开（便于你后续扩展其他攻击检测）
    enable_rule_engine = os.getenv("RULE_ENGINE", "1") == "1"
    enable_classic_detector = os.getenv("CLASSIC_DETECTOR", "1") == "1"

    # ✅ NEW: 去重策略开关（默认 rule 优先：rule 已告警则抑制 classic 落库/推送）
    suppress_classic_when_rule_alerted = os.getenv("SUPPRESS_CLASSIC_WHEN_RULE_ALERTED", "1") == "1"

    # ✅ NEW: 标志位——rule engine 本次是否已经产出告警
    rule_alerted = False
    rule_alert_ids: List[int] = []

    # ✅ rule engine debug container (always defined)
    debug_engine: Dict[str, Any] = {
        "engine_enabled": enable_rule_engine,
        "engine_alerted": False,
        "engine_alert_ids": [],
        "engine_alerts": [],
        "engine_error": None,
        "engine_event": None,
    }

    try:
        parsed = parse_ssh_failed(norm_msg)
    except Exception as e:
        if debug:
            return {
                "ok": True,
                "id": row.id,
                "parsed": False,
                "error": f"parse_error: {repr(e)}",
                "norm_msg": norm_msg[:300],
                "rule_engine": debug_engine,
            }
        return {"ok": True, "id": row.id}

    if parsed:
        # 给 parsed 塞 host/source，避免 detector 聚合缺字段
        if isinstance(parsed, dict):
            parsed.setdefault("host", row.host)
            parsed.setdefault("source", row.source)
        else:
            try:
                if not getattr(parsed, "host", None):
                    setattr(parsed, "host", row.host)
            except Exception:
                pass
            try:
                if not getattr(parsed, "source", None):
                    setattr(parsed, "source", row.source)
            except Exception:
                pass

        # -----------------------------
        # ✅ 1) Rule Engine detect（未来扩展更多规则：HTTP/WEB/端口扫描等）
        # -----------------------------
        if enable_rule_engine:
            try:
                if isinstance(parsed, dict):
                    ev = build_event_from_ssh_failed(parsed, row)
                else:
                    ev = {
                        "log_source": "ssh",
                        "ts": int(time.time()),
                        "src_ip": getattr(parsed, "ip", "") or getattr(parsed, "attack_ip", "") or "",
                        "username": getattr(parsed, "user", "") or getattr(parsed, "username", "") or "",
                        "outcome": "fail",
                        "host": getattr(row, "host", None),
                        "source": getattr(row, "source", None),
                        "raw_id": getattr(row, "id", None),
                        "raw": getattr(parsed, "raw", None),
                    }

                debug_engine["engine_event"] = ev
                engine_alerts = det_engine.evaluate(ev) or []
                debug_engine["engine_alerts"] = engine_alerts
                debug_engine["engine_alerted"] = bool(engine_alerts)

                if engine_alerts:
                    for ea in engine_alerts:
                        rule_id = ea.get("rule_id") or ea.get("alert_type") or "RULE_UNKNOWN"
                        severity = ea.get("severity") or "MEDIUM"
                        attack_ip = ea.get("src_ip") or ea.get("attack_ip") or ""
                        window_sec = ea.get("window_sec") or ea.get("window_seconds") or 0

                        cnt = ea.get("count")
                        if cnt is None:
                            cnt = ea.get("distinct_count")
                        cnt = int(cnt or 0)

                        # ✅✅✅ evidence 必须是字符串（DB 兼容）
                        evidence = safe_evidence(ea)

                        # ✅✅✅ rule engine 告警加前缀，区分来源
                        ra = Alert(
                            alert_type=f"RULE::{str(rule_id)}",
                            severity=str(severity),
                            attack_ip=str(attack_ip),
                            host=row.host,
                            count=cnt,
                            window_seconds=int(window_sec or 0),
                            evidence=evidence,
                        )
                        db.add(ra)
                        db.commit()
                        db.refresh(ra)
                        debug_engine["engine_alert_ids"].append(ra.id)

                        # ✅ NEW: 记录 rule 告警标志，用于后续抑制 classic
                        rule_alerted = True
                        rule_alert_ids.append(ra.id)

                        try:
                            publish_alert(
                                {
                                    "id": str(ra.id),
                                    "alert_type": ra.alert_type,
                                    "severity": ra.severity,
                                    "attack_ip": ra.attack_ip,
                                    "host": ra.host,
                                    "count": str(ra.count),
                                    "window_seconds": str(ra.window_seconds),
                                    "evidence": ra.evidence,
                                    "created_at": fmt_cn(getattr(ra, "created_at", None)),
                                }
                            )
                        except Exception:
                            pass

            except Exception as e:
                debug_engine["engine_error"] = repr(e)

        # -----------------------------
        # ✅ 2) Classic detector detect（保留：便于对照实验/回归；但默认被 rule 去重抑制）
        # -----------------------------
        if enable_classic_detector:
            if rule_alerted and suppress_classic_when_rule_alerted:
                # ✅ 仍然让 classic “算一下”用于 debug，但不落库、不推 WS
                classic_preview = None
                try:
                    try:
                        classic_preview = detect_ssh_bruteforce(parsed, db)
                    except TypeError:
                        classic_preview = detect_ssh_bruteforce(parsed)
                except Exception as e:
                    detector_error = repr(e)
                    classic_preview = None

                if debug:
                    return {
                        "ok": True,
                        "id": row.id,
                        "parsed": True,
                        "rule_alerted": True,
                        "rule_alert_ids": rule_alert_ids,
                        "classic_suppressed": True,
                        "classic_preview": classic_preview,
                        "detector_error": detector_error,
                        "norm_msg": norm_msg[:300],
                        "parsed_obj": parsed,
                        "rule_engine": debug_engine,
                        "note": "rule engine already alerted; classic detector suppressed (no DB/WS)",
                    }
                return {"ok": True, "id": row.id}

            # ✅ 未触发 rule（或关闭去重）时：classic 正常落库/推送
            try:
                try:
                    alert_data = detect_ssh_bruteforce(parsed, db)
                except TypeError:
                    alert_data = detect_ssh_bruteforce(parsed)
            except Exception as e:
                detector_error = repr(e)
                alert_data = None

            if alert_data:
                alert = Alert(
                    alert_type=alert_data["alert_type"],
                    severity=alert_data["severity"],
                    attack_ip=alert_data["attack_ip"],
                    host=row.host,
                    count=alert_data["count"],
                    window_seconds=alert_data["window_seconds"],
                    evidence=safe_evidence(alert_data["evidence"]),
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)

                try:
                    publish_alert(
                        {
                            "id": str(alert.id),
                            "alert_type": alert.alert_type,
                            "severity": alert.severity,
                            "attack_ip": alert.attack_ip,
                            "host": alert.host,
                            "count": str(alert.count),
                            "window_seconds": str(alert.window_seconds),
                            "evidence": alert.evidence,
                            "created_at": fmt_cn(getattr(alert, "created_at", None)),
                        }
                    )
                except Exception:
                    pass

                if debug:
                    return {
                        "ok": True,
                        "id": row.id,
                        "parsed": True,
                        "rule_alerted": rule_alerted,
                        "rule_alert_ids": rule_alert_ids,
                        "classic_alerted": True,
                        "classic_alert_id": alert.id,
                        "norm_msg": norm_msg[:300],
                        "parsed_obj": parsed,
                        "alert_data": alert_data,
                        "rule_engine": debug_engine,
                    }

    if debug:
        return {
            "ok": True,
            "id": row.id,
            "parsed": bool(parsed),
            "rule_alerted": rule_alerted,
            "rule_alert_ids": rule_alert_ids,
            "classic_alerted": bool(alert_data),
            "detector_error": detector_error,
            "norm_msg": norm_msg[:300],
            "parsed_obj": parsed,
            "alert_data": alert_data,
            "rule_engine": debug_engine,
        }

    return {"ok": True, "id": row.id}


# -----------------------------
# ✅ 历史日志：分页 + 过滤（只查库，不影响实时）
# -----------------------------
@app.get(
    "/logs/recent",
    tags=["Logs"],
    summary="Query recent raw logs",
    description="Query raw logs from database with optional filters and cursor pagination. Returns logs in chronological order (old -> new).",
    response_model=list[RawLogOut],
)
def list_recent_logs(
    limit: int = Query(200, ge=1, le=2000),
    before_id: Optional[int] = Query(None, description="分页游标：返回 id < before_id 的更早日志"),
    source: Optional[str] = None,
    host: Optional[str] = None,
    level: Optional[str] = None,
    q: Optional[str] = Query(None, description="message 模糊搜索"),
    db: Session = Depends(get_db),
):
    stmt = select(RawLog)

    conds = []
    if before_id is not None:
        conds.append(RawLog.id < before_id)
    if source and source.strip():
        conds.append(RawLog.source == source.strip())
    if host and host.strip():
        conds.append(RawLog.host == host.strip())
    if level and level.strip():
        lv = level.strip().upper()
        conds.append(RawLog.level.ilike(f"%{lv}%"))
    if q and q.strip():
        kw = q.strip()
        conds.append(RawLog.message.ilike(f"%{kw}%"))

    if conds:
        stmt = stmt.where(and_(*conds))

    stmt = stmt.order_by(RawLog.id.desc()).limit(limit)
    rows = db.execute(stmt).scalars().all()
    rows.reverse()  # 旧 -> 新

    return [
        RawLogOut(
            id=x.id,
            source=x.source,
            host=x.host,
            level=x.level,
            message=x.message,
            created_at=fmt_cn(getattr(x, "created_at", None)) if getattr(x, "created_at", None) else None,
        )
        for x in rows
    ]


@app.get(
    "/alerts",
    tags=["Alerts"],
    summary="Query latest alerts",
    description="Query latest alerts from database (newest first).",
    response_model=list[AlertOut],
)
def list_alerts(limit: int = 50, db: Session = Depends(get_db)):
    stmt = select(Alert).order_by(Alert.id.desc()).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return [
        AlertOut(
            id=a.id,
            alert_type=a.alert_type,
            severity=a.severity,
            attack_ip=a.attack_ip,
            host=a.host,
            count=a.count,
            window_seconds=a.window_seconds,
            evidence=a.evidence,
            created_at=fmt_cn(getattr(a, "created_at", None)),
        )
        for a in rows
    ]


# -----------------------------
# WS helpers
# -----------------------------
async def _xread_threadsafe(key: str, last_id: str, block_ms: int = 2000, count: int = 50):
    return await asyncio.to_thread(stream_xread, key, last_id, block_ms, count)


async def _send_safe(ws: WebSocket, payload: dict) -> bool:
    try:
        await ws.send_json(payload)
        return True
    except WebSocketDisconnect:
        return False
    except Exception:
        return False


def _stream_latest_id(key: str) -> str:
    r = get_redis()
    try:
        items = r.xrevrange(key, count=1)
        if not items:
            return "0-0"
        latest_id, _ = items[0]
        return str(latest_id)
    except Exception:
        return "0-0"


async def _latest_id_threadsafe(key: str) -> str:
    return await asyncio.to_thread(_stream_latest_id, key)


# -----------------------------
# ✅ 实时日志 WS：不回放数据库，但也不漏“刚连接时的消息”
# -----------------------------
@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    await ws.accept()
    last_id = await _latest_id_threadsafe(RAWLOG_STREAM_KEY)

    try:
        while True:
            try:
                res = await _xread_threadsafe(RAWLOG_STREAM_KEY, last_id, block_ms=2000, count=50)
            except Exception:
                ok = await _send_safe(ws, {"type": "status", "data": {"redis": "down", "stream": "rawlog"}})
                if not ok:
                    return
                await asyncio.sleep(1)
                continue

            if not res:
                ok = await _send_safe(ws, {"type": "ping"})
                if not ok:
                    return
                continue

            for _, entries in res:
                for entry_id, fields in entries:
                    last_id = entry_id
                    ok = await _send_safe(ws, {"type": "log", "data": fields})
                    if not ok:
                        return

            await asyncio.sleep(0)

    finally:
        try:
            await ws.close()
        except Exception:
            pass


# -----------------------------
# ✅ 实时告警 WS：同理
# -----------------------------
@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    last_id = await _latest_id_threadsafe(ALERT_STREAM_KEY)

    try:
        while True:
            try:
                res = await _xread_threadsafe(ALERT_STREAM_KEY, last_id, block_ms=2000, count=50)
            except Exception:
                ok = await _send_safe(ws, {"type": "status", "data": {"redis": "down", "stream": "alert"}})
                if not ok:
                    return
                await asyncio.sleep(1)
                continue

            if not res:
                ok = await _send_safe(ws, {"type": "ping"})
                if not ok:
                    return
                continue

            for _, entries in res:
                for entry_id, fields in entries:
                    last_id = entry_id
                    ok = await _send_safe(ws, {"type": "alert", "data": fields})
                    if not ok:
                        return

            await asyncio.sleep(0)

    finally:
        try:
            await ws.close()
        except Exception:
            pass
