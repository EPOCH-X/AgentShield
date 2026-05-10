"""
[R7] SQLAlchemy ORM — 테스트 결과
"""

from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB

from backend.database import Base


class TestResult(Base):
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True)
    session_id = Column(UUID(as_uuid=True), ForeignKey("test_sessions.id"), index=True)
    phase = Column(Integer, nullable=False, index=True)  # 1/2/3/4
    attack_pattern_id = Column(Integer, ForeignKey("attack_patterns.id"), nullable=True)
    seed_id = Column(String(36), index=True)  # DPO 쌍 매칭용 시드 UUID
    round = Column(Integer, nullable=True)  # Phase 2 라운드 번호
    attack_prompt = Column(Text)
    target_response = Column(Text)
    judgment = Column(String(20), index=True)  # vulnerable/safe/ambiguous
    judgment_layer = Column(Integer)  # 1(규칙)/2(LLM)/3(수동)
    judgment_confidence = Column(Float)
    manual_review_needed = Column(Boolean, default=False, index=True)
    severity = Column(String(10))
    category = Column(String(10))
    subcategory = Column(String(50), nullable=True)
    detail = Column(Text, nullable=True)  # Judge 판정 상세 사유
    defense_code = Column(Text, nullable=True)
    defended_response = Column(Text, nullable=True)  # Phase 3 방어 응답 (방어 코드 적용 후 챗봇 응답)
    defense_reviewed = Column(Boolean, default=False)
    verify_result = Column(String(20), nullable=True)  # blocked/bypassed/mitigated
    mitre_technique_id = Column(String(20), nullable=True, index=True)  # MITRE ATT&CK T-ID
    # ── 멀티에이전트 토론 판정 결과 (judge_graph) ──
    p_vulnerable = Column(Float, nullable=True)        # 확률: vulnerable
    p_safe = Column(Float, nullable=True)              # 확률: safe
    probability_judgment = Column(String(20), nullable=True)   # 확률 단독 판정
    consensus_judgment = Column(String(20), nullable=True)     # 토론 합의 판정
    judgment_alignment = Column(String(20), nullable=True)     # aligned/conflict/error
    reason_sources = Column(JSONB, nullable=True)              # {final/consensus/safe_side/vulnerable_side}
    matched_patterns = Column(JSONB, nullable=True)            # 패턴 매칭 결과 리스트
    created_at = Column(DateTime, server_default=func.now())
