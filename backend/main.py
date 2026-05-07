"""
[R7] FastAPI 앱 엔트리포인트
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
import backend.models  # noqa: F401 — ORM 테이블을 Base.metadata에 등록
from backend.api import scan, report, monitoring, auth, vector_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AgentShield",
    description="AI Agent 보안 테스트 + 직원 AI 사용 모니터링 플랫폼",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scan.router, prefix="/api/v1/scan", tags=["scan"])
app.include_router(vector_admin.router, prefix="/api/v1/vector", tags=["vector"])
app.include_router(report.router, prefix="/api/v1/report", tags=["report"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])


@app.get("/health")
async def health():
    return {"status": "ok"}
