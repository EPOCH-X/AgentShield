"""
[R7] FastAPI 앱 엔트리포인트
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from backend.database import init_db
import backend.models  # noqa: F401 — ORM 테이블을 Base.metadata에 등록
from backend.api import scan, report, monitoring, auth, vector_admin, policy_export


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


# ── Security headers ─────────────────────────────────────────────────────────
# OWASP 권장 보안 헤더. HSTS는 HTTPS 환경에서만 의미가 있으므로 ENV로 토글.
_ENABLE_HSTS = os.getenv("SECURITY_ENABLE_HSTS", "false").lower() == "true"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if _ENABLE_HSTS:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ── CORS — 명시적 허용 메서드/헤더 ────────────────────────────────────────────
# 와일드카드(`*`)는 credentials=True 와 결합 시 권장되지 않는다.
_CORS_ORIGINS = [
    o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=600,
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scan.router, prefix="/api/v1/scan", tags=["scan"])
app.include_router(vector_admin.router, prefix="/api/v1/vector", tags=["vector"])
app.include_router(report.router, prefix="/api/v1/report", tags=["report"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])
app.include_router(policy_export.router, prefix="/api/v1/policy-export", tags=["policy-export"])


@app.get("/health")
async def health():
    return {"status": "ok"}
