"""
[R7] SQLAlchemy ORM — 공격 패턴
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, func

from backend.database import Base


class AttackPattern(Base):
    __tablename__ = "attack_patterns"

    id = Column(Integer, primary_key=True)
    prompt_text = Column(Text, nullable=False)
    category = Column(String(10), nullable=False, index=True)  # LLM01/02/06/07
    subcategory = Column(String(50), nullable=True)
    severity = Column(String(10), default="Medium")
    source = Column(String(50))  # necent/jailbreakbench/harmbench/custom
    language = Column(String(10), default="en")
    created_at = Column(DateTime, server_default=func.now())
