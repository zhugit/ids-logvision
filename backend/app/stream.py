import os
import json
import time
import redis
from typing import Dict, Any, Optional, List, Tuple
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "").strip()
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

RAWLOG_STREAM_KEY = "ids:rawlog"
ALERT_STREAM_KEY = "ids:alert"


def _to_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _normalize(data: Dict[str, Any]) -> Dict[str, str]:
    return {str(k): _to_str(v) for k, v in (data or {}).items()}


class RedisClientManager:
    """懒连接 + 自动重建"""
    def __init__(self) -> None:
        self._client: Optional[redis.Redis] = None
        self._last_fail_ts: float = 0.0

    def _build_client(self) -> redis.Redis:
        if REDIS_URL:
            return redis.Redis.from_url(REDIS_URL, decode_responses=True)
        return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

    def get(self) -> redis.Redis:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def reset(self) -> None:
        self._client = None

    def ping(self) -> bool:
        try:
            return bool(self.get().ping())
        except Exception:
            self._last_fail_ts = time.time()
            self.reset()
            return False


_mgr = RedisClientManager()


# ✅✅✅ 兼容你 main.py 里可能写的：from .stream import get_redis
def get_redis() -> redis.Redis:
    """
    兼容导出：返回当前可用的 redis client（断线会自动重建）
    """
    return _mgr.get()


# ✅✅✅ 兼容老代码：如果还有人写 r.xread / r.xadd
class _RedisProxy:
    def __getattr__(self, name: str):
        c = _mgr.get()
        return getattr(c, name)


r = _RedisProxy()


# -----------------------
# 发布（写 Stream）
# -----------------------
def publish_rawlog(data: Dict[str, Any]) -> Optional[str]:
    payload = _normalize(data)
    try:
        return _mgr.get().xadd(RAWLOG_STREAM_KEY, payload, maxlen=5000, approximate=True)
    except Exception:
        _mgr.reset()
        return None


def publish_alert(data: Dict[str, Any]) -> Optional[str]:
    payload = _normalize(data)
    try:
        return _mgr.get().xadd(ALERT_STREAM_KEY, payload, maxlen=2000, approximate=True)
    except Exception:
        _mgr.reset()
        return None


# -----------------------
# 消费（读 Stream）——给 WS 用
# -----------------------
XReadResult = List[Tuple[str, List[Tuple[str, Dict[str, str]]]]]

def stream_xread(key: str, last_id: str, block_ms: int = 2000, count: int = 50) -> XReadResult:
    """
    安全的 xread：
    - 内部获取 redis client
    - 异常自动 reset，下次自动重建
    - 抛异常给上层（WS 那边负责 sleep + 重试）
    """
    try:
        c = _mgr.get()
        return c.xread({key: last_id}, block=block_ms, count=count)  # type: ignore
    except Exception:
        _mgr.reset()
        raise


# -----------------------
# 诊断
# -----------------------
def redis_info() -> Dict[str, Any]:
    try:
        info = _mgr.get().info("server")
        return {
            "ping": True,
            "run_id": info.get("run_id"),
            "redis_version": info.get("redis_version"),
            "mode": info.get("redis_mode"),
            "url": REDIS_URL or None,
            "host": None if REDIS_URL else REDIS_HOST,
            "port": None if REDIS_URL else REDIS_PORT,
            "db": None if REDIS_URL else REDIS_DB,
        }
    except Exception as e:
        _mgr.reset()
        return {
            "ping": False,
            "error": repr(e),
            "url": REDIS_URL or None,
            "host": None if REDIS_URL else REDIS_HOST,
            "port": None if REDIS_URL else REDIS_PORT,
            "db": None if REDIS_URL else REDIS_DB,
        }


def stream_lengths() -> Dict[str, Any]:
    try:
        c = _mgr.get()
        return {
            "rawlog_key": RAWLOG_STREAM_KEY,
            "alert_key": ALERT_STREAM_KEY,
            "rawlog_xlen": int(c.xlen(RAWLOG_STREAM_KEY)),
            "alert_xlen": int(c.xlen(ALERT_STREAM_KEY)),
        }
    except Exception as e:
        _mgr.reset()
        return {
            "error": repr(e),
            "rawlog_key": RAWLOG_STREAM_KEY,
            "alert_key": ALERT_STREAM_KEY,
        }


def ensure_streams() -> Dict[str, Any]:
    try:
        c = _mgr.get()
        created = {"rawlog_created": False, "alert_created": False}

        if not c.exists(RAWLOG_STREAM_KEY):
            tmp_id = c.xadd(RAWLOG_STREAM_KEY, {"_init": "1"})
            c.xdel(RAWLOG_STREAM_KEY, tmp_id)
            created["rawlog_created"] = True

        if not c.exists(ALERT_STREAM_KEY):
            tmp_id = c.xadd(ALERT_STREAM_KEY, {"_init": "1"})
            c.xdel(ALERT_STREAM_KEY, tmp_id)
            created["alert_created"] = True

        return {"ok": True, **created}
    except Exception as e:
        _mgr.reset()
        return {"ok": False, "error": repr(e)}
