"""
[R7] SQLAlchemy ORM — 위반 기록 (스키마: R7 / 비즈니스 로직: R5)
"""

from sqlalchemy import Column, Integer, BigInteger, String, Text, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID

from backend.database import Base


class Violation(Base):
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True)
    employee_id = Column(UUID(as_uuid=True), ForeignKey("employees.id"), index=True)
    violation_type = Column(String(20), nullable=False)
    severity = Column(String(10), nullable=False)
    description = Column(Text)
    evidence_log_id = Column(BigInteger, ForeignKey("usage_logs.id"), nullable=True)
    sanction = Column(String(50))
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
