from __future__ import annotations

import re
from typing import Any, Dict, Optional


# 兼容常见 Nginx combined / common：
# 1.2.3.4 - - [01/Jan/2026:12:00:01 +0800] "GET /admin HTTP/1.1" 404 153 "-" "Mozilla/5.0"
# 也兼容没有 referer/ua 的 common 形式：... "GET /admin HTTP/1.1" 404 153
_NGINX_ACCESS_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+'                    # 1.2.3.4
    r'(?P<ident>\S+)\s+'                      # -
    r'(?P<user>\S+)\s+'                       # -
    r'\[(?P<time>[^\]]+)\]\s+'                # [01/Jan/2026:12:00:01 +0800]
    r'"(?P<method>[A-Z]+)\s+'                 # "GET
    r'(?P<uri>\S+)\s+'                        # /admin
    r'(?P<proto>[^"]+)"\s+'                   # HTTP/1.1"
    r'(?P<status>\d{3})\s+'                   # 404
    r'(?P<body_bytes>\S+)'                    # 153 or -
    r'(?:\s+"(?P<referer>[^"]*)")?'           # "-"  (optional)
    r'(?:\s+"(?P<ua>[^"]*)")?'                # "Mozilla/5.0" (optional)
    r'\s*$'
)


def parse_http_access(message: str) -> Optional[Dict[str, Any]]:
    if not message:
        return None

    line = message.strip().replace('\\"', '"')
    m = _NGINX_ACCESS_RE.match(line)
    if not m:
        return None

    gd = m.groupdict()

    try:
        body_bytes = int(gd.get("body_bytes") or 0)
    except Exception:
        body_bytes = 0

    return {
        "log_source": "http",
        "src_ip": gd.get("src_ip"),
        "method": gd.get("method"),
        "uri": gd.get("uri"),
        "path": (gd.get("uri") or "").split("?", 1)[0],
        "protocol": gd.get("proto"),
        "status_code": int(gd.get("status")),
        "bytes": body_bytes,
        "referer": gd.get("referer"),
        "user_agent": gd.get("ua"),
        "raw": line,
        "time_raw": gd.get("time"),

        # ✅ 关键：host 必须从 ingest 透传
        "host": None,   # 先占位，下面会补
    }


