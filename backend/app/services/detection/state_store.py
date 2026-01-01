from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import redis
import time


class StateStore:
    """
    用 Redis 维护：
    - 窗口计数：ZSET (score=ts, member=member_id/raw_id)
    - distinct 计数：ZSET (score=ts, member=distinct_value)
    - cooldown 去重：SETNX + EX

    ✅ NEW：
    - 窗口事件快照：HASH (field=member, value=json)
      触发告警时可回填窗口内最近 N 条 events
    """

    def __init__(self, r: redis.Redis, prefix: str = "det"):
        self.r = r
        self.prefix = prefix

    def _k(self, *parts: str) -> str:
        return ":".join([self.prefix, *parts])

    # ----------------------------
    # window count / distinct count
    # ----------------------------
    def window_count(self, key: str, ts: int, window_sec: int, member: str) -> int:
        k = self._k("win", key)
        start = ts - window_sec
        pipe = self.r.pipeline()
        pipe.zadd(k, {member: ts})
        pipe.zremrangebyscore(k, 0, start)
        pipe.zcard(k)
        pipe.expire(k, window_sec + 60)
        _, _, cnt, _ = pipe.execute()
        return int(cnt)

    def window_distinct_count(self, key: str, ts: int, window_sec: int, distinct_value: str) -> int:
        """
        distinct_value 作为 member，score=ts；同一个 distinct_value 在窗口内重复写会覆盖为最新 ts，
        但仍然能保证“窗口内出现过”的 distinct 个数，且会随窗口滑动被清理。
        """
        k = self._k("dst", key)
        start = ts - window_sec
        pipe = self.r.pipeline()
        pipe.zadd(k, {distinct_value: ts})
        pipe.zremrangebyscore(k, 0, start)
        pipe.zcard(k)
        pipe.expire(k, window_sec + 60)
        _, _, cnt, _ = pipe.execute()
        return int(cnt)

    # ----------------------------
    # ✅ NEW: window events snapshot
    # ----------------------------
    def window_record_event(
        self,
        key: str,
        ts: int,
        window_sec: int,
        member: str,
        event_obj: Dict[str, Any],
        keep_last: int = 50,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        ✅ 在做窗口计数的同时，把事件快照写入 HASH，触发时可回填 events

        返回：
          (当前窗口计数cnt, 窗口内最近 keep_last 条事件列表 events)

        事件存储结构：
          - ZSET: det:win:{key}            score=ts, member=member
          - HASH: det:evt:{key}            field=member, value=json(event_obj)
        """
        zkey = self._k("win", key)
        hkey = self._k("evt", key)
        start = ts - window_sec

        # 写入 + 清理窗口外 member
        pipe = self.r.pipeline()
        pipe.zadd(zkey, {member: ts})
        pipe.hset(hkey, member, json.dumps(event_obj, ensure_ascii=False))
        pipe.zremrangebyscore(zkey, 0, start)
        pipe.zcard(zkey)
        pipe.expire(zkey, window_sec + 60)
        pipe.expire(hkey, window_sec + 60)
        _, _, _, cnt, _, _ = pipe.execute()

        # 取窗口内 member（按时间从旧到新）
        members: List[str] = self.r.zrangebyscore(zkey, start + 1, ts)
        # zrangebyscore 返回 bytes
        members = [m.decode() if isinstance(m, (bytes, bytearray)) else str(m) for m in members]

        # 只保留最后 keep_last 条
        if keep_last > 0 and len(members) > keep_last:
            members = members[-keep_last:]

        if not members:
            return int(cnt), []

        raw_list = self.r.hmget(hkey, members)

        events: List[Dict[str, Any]] = []
        for raw in raw_list:
            if not raw:
                continue
            try:
                s = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
                obj = json.loads(s)
                if isinstance(obj, dict):
                    events.append(obj)
            except Exception:
                continue

        return int(cnt), events

    def window_get_events(
        self,
        key: str,
        ts: int,
        window_sec: int,
        keep_last: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        只读取窗口内事件（不写入）
        """
        zkey = self._k("win", key)
        hkey = self._k("evt", key)
        start = ts - window_sec

        members: List[str] = self.r.zrangebyscore(zkey, start + 1, ts)
        members = [m.decode() if isinstance(m, (bytes, bytearray)) else str(m) for m in members]
        if keep_last > 0 and len(members) > keep_last:
            members = members[-keep_last:]

        if not members:
            return []

        raw_list = self.r.hmget(hkey, members)

        events: List[Dict[str, Any]] = []
        for raw in raw_list:
            if not raw:
                continue
            try:
                s = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
                obj = json.loads(s)
                if isinstance(obj, dict):
                    events.append(obj)
            except Exception:
                continue
        return events

    # ----------------------------
    # cooldown
    # ----------------------------
    def cooldown_hit(self, dedup_key: str, cooldown_sec: int) -> bool:
        """
        True  = 允许触发告警
        False = 处于冷却期内，禁止触发
        """
        # ✅ 0 或负数：不启用冷却，永远允许
        if cooldown_sec <= 0:
            return True

        k = self._k("cd", dedup_key)
        now = int(time.time())

        last = self.r.get(k)
        if last is None:
            # 从未触发过：允许，并记录时间
            self.r.set(k, now, ex=cooldown_sec)
            return True

        last_ts = int(last)
        if now - last_ts < cooldown_sec:
            # 仍在冷却期
            return False

        # 冷却期已过：更新时间，允许
        self.r.set(k, now, ex=cooldown_sec)
        return True

    # ----------------------------
    # for fail->success 简化序列
    # ----------------------------
    def record_fail(self, key: str, ts: int, within_sec: int) -> int:
        """记录一次 fail，并返回 within_sec 内 fail 次数"""
        member = f"{ts}"
        return self.window_count(f"{key}:fail", ts, within_sec, member)

    def had_recent_fail_burst(self, key: str, ts: int, within_sec: int, threshold: int) -> bool:
        """判断 within_sec 内 fail 是否 >= threshold"""
        k = self._k("win", f"{key}:fail")
        start = ts - within_sec
        cnt = self.r.zcount(k, start + 1, ts)
        return int(cnt) >= threshold
