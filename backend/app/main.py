from datetime import datetime
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
    get_redis,            # ✅ 需要你在 stream.py 里加这个（上一条我给过完整 stream.py）
    redis_info,
    stream_lengths,
    ensure_streams,
)

from .services.parser.ssh import parse_ssh_failed
from .services.detector.ssh_bruteforce import detect_ssh_bruteforce

app = FastAPI(title="Real-time Log IDS")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # ✅ 启动时确保 Stream key 存在（没有也不影响启动）
    try:
        ensure_streams()
    except Exception:
        pass


@app.get("/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat()}


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
def ingest(payload: IngestLogIn, db: Session = Depends(get_db)):
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
                "created_at": row.created_at.isoformat() if getattr(row, "created_at", None) else "",
            }
        )
    except Exception:
        pass

    # 解析 + 检测
    parsed = parse_ssh_failed(row.message)
    if parsed:
        alert_data = detect_ssh_bruteforce(parsed)
        if alert_data:
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
                        "created_at": alert.created_at.isoformat() if getattr(alert, "created_at", None) else "",
                    }
                )
            except Exception:
                pass

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
            created_at=x.created_at.isoformat() if getattr(x, "created_at", None) else None,
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
            created_at=a.created_at.isoformat() if getattr(a, "created_at", None) else "",
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
    """
    ✅ 关键：获取 Stream 当前最新 entry_id
    - 没有数据：返回 "0-0"
    - 有数据：返回最新一条 id
    """
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

    # ✅ 起点：以“当前stream最新id”为基准，只收之后新增的
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
