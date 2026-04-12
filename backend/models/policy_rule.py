"""
[R7] SQLAlchemy ORM — 정책 규칙 (스키마: R7 / 비즈니스 로직: R5)
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, func

from backend.database import Base


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True)
    rule_name = Column(String(100))
    rule_type = Column(String(20))  # keyword/regex/ratelimit/topic
    pattern = Column(Text)  # JSON
    severity = Column(String(10))
    action = Column(String(20))  # block/warn/log
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
