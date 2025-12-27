from datetime import datetime
from sqlalchemy import String, Text, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), default="manual", index=True)
    host: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    level: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    alert_type: Mapped[str] = mapped_column(String(64), index=True)      # SSH_BRUTEFORCE
    severity: Mapped[str] = mapped_column(String(16), index=True)        # LOW/MEDIUM/HIGH
    attack_ip: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[str] = mapped_column(String(128), default="unknown", index=True)

    count: Mapped[int] = mapped_column(Integer, default=0)
    window_seconds: Mapped[int] = mapped_column(Integer, default=60)

    evidence: Mapped[str] = mapped_column(Text)  # 简单存 JSON 字符串（证据链）
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
