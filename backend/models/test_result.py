"""
[R7] SQLAlchemy ORM — 테스트 결과
"""

from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID

from backend.database import Base


class TestResult(Base):
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True)
    session_id = Column(UUID(as_uuid=True), ForeignKey("test_sessions.id"), index=True)
    phase = Column(Integer, nullable=False, index=True)  # 1/2/3/4
    attack_pattern_id = Column(Integer, ForeignKey("attack_patterns.id"), nullable=True)
    attack_prompt = Column(Text)
    target_response = Column(Text)
    judgment = Column(String(20))  # vulnerable/safe/ambiguous
    judgment_layer = Column(Integer)  # 1(규칙)/2(LLM)/3(수동)
    judgment_confidence = Column(Float)
    manual_review_needed = Column(Boolean, default=False, index=True)
    severity = Column(String(10))
    category = Column(String(10))
    defense_code = Column(Text, nullable=True)
    defense_reviewed = Column(Boolean, default=False)
    verify_result = Column(String(20), nullable=True)  # blocked/bypassed/mitigated
    created_at = Column(DateTime, server_default=func.now())
