# backend/app/services/enricher/url_existence.py
from __future__ import annotations

import time
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx


@dataclass
class UrlCheckResult:
    exists: Optional[bool]   # True / False / None(unknown)
    status: Optional[int]    # HTTP status or None
    note: str = ""           # abnormal / timeout / invalid_host ...
    checked_at: int = 0      # unix ts


class UrlExistenceChecker:
    """
    轻量 URL 存在性验证：
    - 只做 HEAD/GET，不跟随重定向
    - 401/403 视为“存在”（很关键）
    - TTL 缓存：避免重复请求
    - Host allowlist：默认只允许 zmqzmq.cn（防 SSRF）
    """

    def __init__(
        self,
        allowed_hosts: Optional[set[str]] = None,
        ttl_seconds: int = 600,
        max_cache: int = 1024,
        timeout_seconds: float = 3.0,
    ):
        self.allowed_hosts = allowed_hosts or {"zmqzmq.cn"}
        self.ttl_seconds = ttl_seconds
        self.max_cache = max_cache
        self.timeout_seconds = timeout_seconds

        self._lock = threading.Lock()
        self._cache: Dict[str, UrlCheckResult] = {}

    def _prune_if_needed(self):
        # 简单裁剪：超过 max_cache 时删掉最旧的一批
        if len(self._cache) <= self.max_cache:
            return
        items = sorted(self._cache.items(), key=lambda kv: kv[1].checked_at)
        drop = max(1, len(items) - self.max_cache)
        for k, _ in items[:drop]:
            self._cache.pop(k, None)

    def _allowed(self, url: str) -> bool:
        try:
            u = urlparse(url)
            host = (u.hostname or "").lower()
            return host in self.allowed_hosts
        except Exception:
            return False

    def check(self, url: str) -> Dict[str, Any]:
        now = int(time.time())

        # host allowlist
        if not self._allowed(url):
            return UrlCheckResult(
                exists=None, status=None, note="invalid_host", checked_at=now
            ).__dict__

        # cache
        with self._lock:
            cached = self._cache.get(url)
            if cached and (now - cached.checked_at) <= self.ttl_seconds:
                return cached.__dict__

        # network check
        try:
            timeout = httpx.Timeout(self.timeout_seconds)
            with httpx.Client(follow_redirects=False, timeout=timeout) as client:
                r = client.head(url)
                status = r.status_code

                # 有些站点不支持 HEAD，返回 405/400，退化用 GET（不跟随重定向）
                if status in (400, 405):
                    r = client.get(url)
                    status = r.status_code

            # 判定存在性（行业常用口径）
            if status in (200, 301, 302, 401, 403):
                result = UrlCheckResult(True, status, "", now)
            elif status == 404:
                result = UrlCheckResult(False, status, "", now)
            elif 500 <= status <= 599:
                # 服务端错误：一般说明“路径可能存在但异常”，给 exists=True + note
                result = UrlCheckResult(True, status, "abnormal", now)
            else:
                # 其他状态：给 unknown
                result = UrlCheckResult(None, status, "unknown_status", now)

        except Exception:
            result = UrlCheckResult(None, None, "timeout_or_error", now)

        with self._lock:
            self._cache[url] = result
            self._prune_if_needed()

        return result.__dict__


# ✅ 全局单例（你项目里直接 import 用）
url_checker = UrlExistenceChecker(
    allowed_hosts={"zmqzmq.cn"},
    ttl_seconds=600,      # 10 分钟
    max_cache=2048,
    timeout_seconds=3.0,
)
