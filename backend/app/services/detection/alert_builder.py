from __future__ import annotations
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

#from app.services.enricher.url_existence import url_checker


# ✅ 统一对外展示域名（你指定）
PUBLIC_HOST = "zmqzmq.cn"


def _public_host(_: str | None) -> str:
    """把内部资产名统一映射为对外域名展示（不再出现 server1/server2/web-01）。"""
    return PUBLIC_HOST


def _extract_paths(extra: Optional[Dict[str, Any]]) -> List[str]:
    """优先 extra.paths，其次从 extra.events[*].path 抽。"""
    if not extra:
        return []

    out: List[str] = []
    paths = extra.get("paths")
    if isinstance(paths, list):
        for p in paths:
            if isinstance(p, str) and p.strip():
                out.append(p.strip())

    if not out:
        evs = extra.get("events")
        if isinstance(evs, list):
            for e in evs:
                if isinstance(e, dict):
                    p = e.get("path")
                    if isinstance(p, str) and p.strip():
                        out.append(p.strip())

    # 去重保持顺序
    seen = set()
    uniq: List[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _guess_scheme_and_port(rule: Any, event: Dict[str, Any]) -> tuple[str, Optional[int]]:
    """
    http_access 里通常拿不到 https，这里默认 http；
    如果未来你解析器能带 scheme/port，这里会自动用真实值。
    """
    scheme = (event.get("scheme") or "").strip().lower()
    port = event.get("port")

    if scheme in ("http", "https"):
        if port in (None, "", "-", "null"):
            port = 443 if scheme == "https" else 80
        try:
            return scheme, int(port)
        except Exception:
            return scheme, None

    # 没 scheme：根据 port 猜，否则默认 http
    try:
        p = int(port) if port not in (None, "", "-", "null") else None
    except Exception:
        p = None

    if p == 443:
        return "https", 443
    if p == 80:
        return "http", 80
    return "http", p


def _format_url(scheme: str, host: str, port: Optional[int], path: str) -> str:
    scheme = (scheme or "http").strip().lower() or "http"
    host = (host or "").strip() or PUBLIC_HOST
    path = (path or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path

    if port is None:
        return f"{scheme}://{host}{path}"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _build_http_targets(rule: Any, base_event: Dict[str, Any], extra: Optional[Dict[str, Any]]) -> List[str]:
    """HTTP：从 extra.events / paths 生成完整 URL 列表。缺失时给一组常见敏感路径兜底。"""
    scheme0, port0 = _guess_scheme_and_port(rule, base_event)
    host0 = _public_host(base_event.get("host"))

    targets: List[str] = []

    # 优先从 evidence events 还原（每条有 path）
    if extra and isinstance(extra.get("events"), list) and extra["events"]:
        for e in extra["events"]:
            if not isinstance(e, dict):
                continue
            path = e.get("path") or "/"
            scheme, port = _guess_scheme_and_port(rule, {**base_event, **e})
            targets.append(_format_url(scheme, host0, port, str(path)))

    # 退化：从 paths 拼
    if not targets:
        for p in _extract_paths(extra):
            targets.append(_format_url(scheme0, host0, port0, p))

    # 兜底：如果连 path 都没有（极少），给一些常见敏感路径随机/固定组合
    if not targets:
        fallback = ["/admin", "/login", "/phpinfo.php", "/backup.zip", "/api/admin"]
        for p in fallback:
            targets.append(_format_url(scheme0, host0, port0, p))

    # 去重保持顺序
    seen = set()
    uniq: List[str] = []
    for u in targets:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _attack_type_cn(rule: Any) -> str:
    rid = (getattr(rule, "id", "") or "").upper()
    if rid in ("HTTP_PATH_BRUTEFORCE", "HTTP_SCAN", "HTTP_ADMIN_SCAN"):
        return "Web 敏感路径扫描"
    if rid in ("SSH_BRUTEFORCE", "SSH_BRUTE_FORCE"):
        return "SSH 暴力破解"
    if rid in ("SSH_PASSWORD_SPRAY",):
        return "SSH 口令喷洒"
    if rid in ("SSH_FAIL_TO_SUCCESS",):
        return "爆破后成功登录"
    name = getattr(rule, "name", "") or rid or "异常行为告警"
    return name


def _risk(rule: Any) -> str:
    sev = (getattr(rule, "severity", "") or "").upper()
    if "CRIT" in sev or "HIGH" in sev:
        return "high"
    if "MED" in sev:
        return "medium"
    return "low"


def _human_summary_cn(rule: Any, event: Dict[str, Any], extra: Dict[str, Any] | None) -> str:
    rid = (getattr(rule, "id", "") or "").upper()
    src_ip = event.get("src_ip") or "-"
    host = "zmqzmq.cn"

    # HTTP 扫描类
    if rid in ("HTTP_PATH_BRUTEFORCE", "HTTP_SCAN", "HTTP_ADMIN_SCAN"):
        paths = []
        if extra:
            for e in extra.get("events", []):
                p = e.get("path")
                if isinstance(p, str):
                    paths.append(p)
        paths = list(dict.fromkeys(paths))[:3]
        path_text = "、".join(paths) if paths else "多个敏感路径"

        return (
            f"检测到来源 IP {src_ip} 对站点 {host} 发起敏感路径探测请求，"
            f"访问路径包括 {path_text}，"
            f"行为特征符合 Web 后台入口探测/路径枚举，"
            f"可能为入侵前置扫描行为。"
        )

    # SSH 认证攻击
    if rid.startswith("SSH_"):
        port = event.get("port") or 22
        user = event.get("username") or "未知账号"
        atk = "SSH 暴力破解" if "BRUTE" in rid else "SSH 口令喷洒"

        return (
            f"检测到来源 IP {src_ip} 针对 ssh://{host}:{port} 发起异常认证尝试，"
            f"涉及账号 {user}，"
            f"行为模式符合 {atk} 特征，"
            f"存在账户被入侵风险。"
        )

    return f"检测到来源 IP {src_ip} 针对 {host} 的异常访问行为。"

def _url_semantic_tag(path: str) -> str:
    """
    路径语义标签：让证据更像安全产品
    """
    p = (path or "").lower()

    if p in ("/admin", "/admin/"):
        return "后台入口"
    if p in ("/login", "/login/"):
        return "登录页"
    if p.endswith("/phpinfo.php"):
        return "信息泄露高危"
    if p.endswith("/.git/config") or p.startswith("/.git/"):
        return "源码泄露"
    if p.endswith("/wp-login.php"):
        return "WordPress 登录"
    if p.endswith("/backup.zip") or p.endswith("/backup.tar") or p.endswith("/backup.tar.gz"):
        return "备份文件泄露"
    if p.startswith("/api/admin"):
        return "API 后台入口"
    if p.startswith("/test"):
        return "可疑探测路径"

    return "敏感路径探测"


def _normalize_and_enrich_urls(urls: list) -> list[dict]:
    """
    输入:
      - ["http://zmqzmq.cn/admin", ...]
      - [{"url": "...", "tag": "..."} , ...]  (兼容)
    输出:
      - [{"url","path","tag","exists","status","note"}...]
    """
    out: list[dict] = []

    for item in urls:
        if isinstance(item, str):
            url = item.strip()
            tag = ""
        elif isinstance(item, dict):
            url = str(item.get("url", "")).strip()
            tag = str(item.get("tag", "")).strip()
        else:
            continue

        if not url:
            continue

        try:
            u = urlparse(url)
            path = u.path or "/"
        except Exception:
            path = "/"

        if not tag:
            tag = _url_semantic_tag(path)

        out.append({
            "url": url,
            "path": path,
            "tag": tag,
            "exists": None,
            "status": None,
            "note": "",
        })

    return out


def build_alert(
    rule: Any,
    event: Dict[str, Any],
    group_key: str,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    rid = (getattr(rule, "id", "") or "").upper()
    host_pub = _public_host(event.get("host"))

    payload: Dict[str, Any] = {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "tags": getattr(rule, "tags", []),
        "log_source": rule.log_source,
        "group_key": group_key,

        "src_ip": event.get("src_ip"),
        # ✅ 前端表格/弹窗都用这个 host：统一域名
        "host": host_pub,

        "username": event.get("username"),
        "port": event.get("port"),
        "ts": event.get("ts"),
        "raw_id": event.get("raw_id"),

        # ✅ 可选：保留内部资产标签，便于你以后溯源，但 UI 不用展示
        "asset": {
            "internal_host": event.get("host"),
            "public_host": host_pub,
        },
    }

    if extra:
        payload.update(extra)

    # ✅ assessment：前端“涉及目标 URL”从这里拿（必须有）
    assessment: Dict[str, Any] = {
        "attack_type": _attack_type_cn(rule),
        "risk": _risk(rule),
        "targets": [],
        "paths": _extract_paths(extra),
    }

    if rid in ("HTTP_PATH_BRUTEFORCE", "HTTP_SCAN", "HTTP_ADMIN_SCAN"):
        # 1) 原始目标（保持兼容：List[str]）
        assessment["targets"] = _build_http_targets(rule, event, extra)

        # 2) ✅ 新增：结构化目标（带语义标签 + 是否存在）
        #    前端弹窗优先用 assessment.target_urls 渲染即可
        try:
            assessment["target_urls"] = _normalize_and_enrich_urls(assessment["targets"])
        except Exception:
            assessment["target_urls"] = []

    elif rid.startswith("SSH_"):
        port = event.get("port") or 22
        assessment["targets"] = [f"ssh://{host_pub}:{port}"]
        # SSH 不做 HTTP 存在性探测（避免误判），给空数组保持字段一致
        assessment["target_urls"] = []

    payload["assessment"] = assessment

    # ✅ 产品级描述：前端优先展示这个
    payload["human_summary_cn"] = _human_summary_cn(rule, event, extra)

    # 兼容旧字段
    payload["summary"] = f"{rule.name} | {group_key}"

    return payload
