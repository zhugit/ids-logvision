import re
from typing import Optional, Dict

# 兼容：
# Failed password for root from 1.2.3.4 port 22 ssh2
# Failed password for invalid user root from 1.2.3.4 port 22 ssh2
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)

def parse_ssh_failed(message: str) -> Optional[Dict[str, str]]:
    if not message:
        return None

    m = FAILED_RE.search(message)
    if not m:
        return None

    user = m.group("user")
    ip = m.group("ip")
    port = m.group("port") or ""

    return {
        "user": user,
        "ip": ip,
        "attack_ip": ip,
        "port": port,
        "event": "SSH_LOGIN_FAILED",
        "raw": message,   # ✅ 关键：给 detector 存入 evidence 的原始片段
    }
