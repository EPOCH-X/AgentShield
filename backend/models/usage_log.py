"""
[R7] SQLAlchemy ORM — 사용 로그 (스키마: R7 / 비즈니스 로직: R5)
"""

from sqlalchemy import Column, BigInteger, Text, String, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID

from backend.database import Base


class UsageLog(Base):
    __tablename__ = "usage_logs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    employee_id = Column(UUID(as_uuid=True), ForeignKey("employees.id"), index=True)
    request_content = Column(Text)
    response_content = Column(Text)
    target_service = Column(String(50))
    policy_violation = Column(String(20), index=True)  # none/P1_leak/P2_misuse/P3_ratelimit
    severity = Column(String(10))
    action_taken = Column(String(20))  # allowed/warned/blocked
    request_at = Column(DateTime, server_default=func.now())
