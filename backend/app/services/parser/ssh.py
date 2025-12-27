import re
from typing import Optional, Dict

# 典型例子：
# "Failed password for root from 192.168.1.10 port 52144 ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_ssh_failed(message: str) -> Optional[Dict[str, str]]:
    m = FAILED_RE.search(message)
    if not m:
        return None
    return {
        "user": m.group("user"),
        "ip": m.group("ip"),
        "event": "SSH_LOGIN_FAILED",
    }
