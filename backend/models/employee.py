"""
[R7] SQLAlchemy ORM — 직원 (스키마: R7 / 비즈니스 로직: R5)
"""

import uuid

from sqlalchemy import Column, String, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import UUID

from backend.database import Base


class Employee(Base):
    __tablename__ = "employees"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    employee_id = Column(String(50), unique=True, nullable=False)
    department = Column(String(100))
    name = Column(String(100))
    role = Column(String(50))  # user / admin / auditor
    status = Column(String(20), default="active")
    daily_limit = Column(Integer, default=200)
    created_at = Column(DateTime, server_default=func.now())
