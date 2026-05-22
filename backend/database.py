"""
[R7] 데이터베이스 세션 관리
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from backend.config import settings

DATABASE_URL = settings.DATABASE_URL

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


async def init_db():
    # 모델 모듈을 import해야 Base.metadata에 테이블이 등록됨
    import backend.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS categories TEXT"))
        await conn.execute(text("ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_total INTEGER DEFAULT 0"))
        await conn.execute(text("ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_false_refusals INTEGER DEFAULT 0"))
        await conn.execute(text("ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_rate NUMERIC(5, 4) DEFAULT 0"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20)"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS p_vulnerable DOUBLE PRECISION"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS p_safe DOUBLE PRECISION"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS probability_judgment VARCHAR(20)"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS consensus_judgment VARCHAR(20)"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS judgment_alignment VARCHAR(20)"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS reason_sources JSONB"))
        await conn.execute(text("ALTER TABLE test_results ADD COLUMN IF NOT EXISTS matched_patterns JSONB"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_results_mitre ON test_results(mitre_technique_id)"))
