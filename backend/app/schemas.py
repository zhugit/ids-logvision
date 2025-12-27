from pydantic import BaseModel
from typing import Optional, Any

# 兼容 Pydantic v2 的 from_attributes（FastAPI 新版基本是 v2）
try:
    from pydantic import ConfigDict
except Exception:
    ConfigDict = None  # type: ignore


class IngestLogIn(BaseModel):
    source: str
    host: str
    level: str
    message: str


class RawLogOut(BaseModel):
    id: int
    source: str
    host: str
    level: str
    message: str
    created_at: Optional[str] = None

    # Pydantic v2
    if ConfigDict is not None:
        model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    alert_type: str
    severity: str
    attack_ip: str
    host: str
    count: int
    window_seconds: int
    evidence: Any
    created_at: str

    if ConfigDict is not None:
        model_config = ConfigDict(from_attributes=True)
