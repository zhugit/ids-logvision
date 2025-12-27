from datetime import datetime, timezone, timedelta
import asyncio
from typing import Optional, Any

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

app = FastAPI(title="Real-time Log IDS")

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


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    try:
        ensure_streams()
    except Exception:
        pass


@app.get("/health")
def health():
    # ✅ 健康检查也返回中国时间，避免你调试时混淆
    return {"ok": True, "time": now_cn().strftime("%Y-%m-%d %H:%M:%S")}


# -----------------------------
# ✅ Debug: 你浏览器访问 /debug/redis 不再 404
# -----------------------------
@app.get("/debug/redis")
def debug_redis():
    return {
        "redis": redis_info(),
        "streams": stream_lengths(),
        "ensure": ensure_streams(),
    }


# -----------------------------
# Ingest
# -----------------------------
@app.post("/ingest")
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
                # ✅ 直接推送中国时间字符串
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

    try:
        parsed = parse_ssh_failed(norm_msg)
    except Exception as e:
        # parse 本身报错
        if debug:
            return {
                "ok": True,
                "id": row.id,
                "parsed": False,
                "error": f"parse_error: {repr(e)}",
                "norm_msg": norm_msg[:300],
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

        # detector 可能需要 db（用窗口查库计数），优先 detect(parsed, db)
        try:
            alert_data = detect_ssh_bruteforce(parsed, db)
        except TypeError:
            # 兼容 detector 只收一个参数的写法
            alert_data = detect_ssh_bruteforce(parsed)
        except Exception as e:
            detector_error = repr(e)

        if alert_data:
            # ✅ 同理：不手动传 created_at，让 models default 生效
            alert = Alert(
                alert_type=alert_data["alert_type"],
                severity=alert_data["severity"],
                attack_ip=alert_data["attack_ip"],
                host=row.host,
                count=alert_data["count"],
                window_seconds=alert_data["window_seconds"],
                evidence=alert_data["evidence"],
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
                        # ✅ 直接推送中国时间字符串
                        "created_at": fmt_cn(getattr(alert, "created_at", None)),
                    }
                )
            except Exception:
                pass

            # debug 模式：把 alert_id 也返回，便于你立刻确认 DB 新增
            if debug:
                return {
                    "ok": True,
                    "id": row.id,
                    "parsed": True,
                    "alerted": True,
                    "alert_id": alert.id,
                    "norm_msg": norm_msg[:300],
                    "parsed_obj": parsed,
                    "alert_data": alert_data,
                }

    # debug 模式：明确告诉你到底卡在哪一步
    if debug:
        return {
            "ok": True,
            "id": row.id,
            "parsed": bool(parsed),
            "alerted": bool(alert_data),
            "detector_error": detector_error,
            "norm_msg": norm_msg[:300],
            "parsed_obj": parsed,
            "alert_data": alert_data,
        }

    return {"ok": True, "id": row.id}


# -----------------------------
# ✅ 历史日志：分页 + 过滤（只查库，不影响实时）
# -----------------------------
@app.get("/logs/recent", response_model=list[RawLogOut])
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
            # ✅ 统一返回中国时间字符串
            created_at=fmt_cn(getattr(x, "created_at", None)) if getattr(x, "created_at", None) else None,
        )
        for x in rows
    ]


@app.get("/alerts", response_model=list[AlertOut])
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
            # ✅ 统一返回中国时间字符串
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
