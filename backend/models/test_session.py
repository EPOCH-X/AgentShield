"""
[R7] SQLAlchemy ORM — 테스트 세션
"""

import uuid

from sqlalchemy import Column, Integer, Numeric, String, Text, DateTime, func
from sqlalchemy.dialects.postgresql import UUID

from backend.database import Base


class TestSession(Base):
    __tablename__ = "test_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_name = Column(String(200))
    target_api_url = Column(Text, nullable=False)
    status = Column(String(20), default="pending")  # pending/running/completed/failed
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    # FRR (False Refusal Rate) 통계 — CyberSecEval 4 방법론
    frr_total = Column(Integer, default=0)           # 투입된 정상 요청 수
    frr_false_refusals = Column(Integer, default=0)  # 오탐(vulnerable/ambiguous) 판정 수
    frr_rate = Column(Numeric(5, 4), default=0)      # frr_false_refusals / frr_total
