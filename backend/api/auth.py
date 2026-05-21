"""
[R7] 인증 API — JWT 토큰 발급/검증

[보안 정책]
- Rate limit: (username, IP) 키 기준 5분 윈도에 5회 실패 시 잠금 (잠금 동안 모든 시도 거부)
- 비밀번호: 최소 8자 + 영문/숫자/특수문자 중 2종 이상
- 감사 로그: 모든 login 시도(성공/실패) audit_logs 테이블에 기록
"""

import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import get_db
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ── Rate limit (메모리 카운터) ────────────────────────────────────────────────
_LOGIN_FAIL_WINDOW_SEC = 300       # 5분 윈도
_LOGIN_FAIL_THRESHOLD  = 5         # 5회 실패 시 잠금
_LOGIN_LOCKOUT_SEC     = 900       # 15분 잠금

_login_fails: dict[str, deque[float]] = defaultdict(deque)
_login_lockout_until: dict[str, float] = {}


def _rate_limit_key(username: str, request: Optional[Request]) -> str:
    ip = ""
    if request and request.client:
        ip = request.client.host or ""
    return f"{username.lower()}|{ip}"


def _check_login_lockout(key: str) -> None:
    now = time.time()
    until = _login_lockout_until.get(key, 0.0)
    if until > now:
        remain = int(until - now)
        raise HTTPException(
            status_code=429,
            detail=f"로그인 시도 한도 초과. {remain}초 후 다시 시도하세요.",
        )


def _record_login_failure(key: str) -> None:
    now = time.time()
    q = _login_fails[key]
    while q and now - q[0] > _LOGIN_FAIL_WINDOW_SEC:
        q.popleft()
    q.append(now)
    if len(q) >= _LOGIN_FAIL_THRESHOLD:
        _login_lockout_until[key] = now + _LOGIN_LOCKOUT_SEC
        q.clear()


def _reset_login_counter(key: str) -> None:
    _login_fails.pop(key, None)
    _login_lockout_until.pop(key, None)


# ── 비밀번호 정책 ─────────────────────────────────────────────────────────────
_PW_MIN_LEN = 8
_PW_HAS_LOWER = re.compile(r"[a-z]")
_PW_HAS_UPPER = re.compile(r"[A-Z]")
_PW_HAS_DIGIT = re.compile(r"\d")
_PW_HAS_SYMBOL = re.compile(r"[^A-Za-z0-9]")


def _validate_password_strength(password: str) -> None:
    if len(password) < _PW_MIN_LEN:
        raise ValueError(f"비밀번호는 최소 {_PW_MIN_LEN}자 이상이어야 합니다.")
    classes = sum(bool(p.search(password)) for p in (_PW_HAS_LOWER, _PW_HAS_UPPER, _PW_HAS_DIGIT, _PW_HAS_SYMBOL))
    if classes < 2:
        raise ValueError("비밀번호는 영문/숫자/특수문자 중 2종 이상을 포함해야 합니다.")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    username: str
    role: str  # admin / auditor / user


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        _validate_password_strength(v)
        return v

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) < 3:
            raise ValueError("아이디는 최소 3자 이상이어야 합니다.")
        if len(v) > 50:
            raise ValueError("아이디는 50자를 넘을 수 없습니다.")
        return v


def _infer_user_role(user: User) -> str:
    if (user.email or "").lower() == "admin@agentshield.io":
        return "admin"
    if (user.name or "").lower() == "admin":
        return "admin"
    return "user"


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInfo:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="인증 정보가 유효하지 않습니다",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "user")
        if username is None:
            raise credentials_exception
        return UserInfo(username=username, role=role)
    except JWTError:
        raise credentials_exception


async def get_current_admin(user: UserInfo = Depends(get_current_user)) -> UserInfo:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return user


async def _write_audit_log(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    request: Optional[Request],
    detail: Optional[str] = None,
    resource: Optional[str] = None,
) -> None:
    """감사 로그 — 실패해도 인증 흐름은 깨지지 않게."""
    from backend.models.audit_log import AuditLog

    try:
        ip = request.client.host if request and request.client else None
        ua = request.headers.get("user-agent") if request else None
        db.add(AuditLog(
            actor=actor[:100],
            action=action[:50],
            resource=resource,
            ip_address=ip,
            user_agent=ua[:255] if ua else None,
            detail=detail,
        ))
        await db.commit()
    except Exception:
        logger.exception("[auth] audit log 작성 실패")


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    key = _rate_limit_key(form_data.username, request)
    _check_login_lockout(key)

    result = await db.execute(select(User).where(User.name == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        _record_login_failure(key)
        await _write_audit_log(
            db, actor=form_data.username or "anonymous",
            action="login_failure", request=request,
            detail="invalid credentials",
        )
        # 잠금 직후면 메시지 다르게
        if _login_lockout_until.get(key, 0.0) > time.time():
            await _write_audit_log(
                db, actor=form_data.username or "anonymous",
                action="login_locked", request=request,
                detail=f"locked for {_LOGIN_LOCKOUT_SEC}s after {_LOGIN_FAIL_THRESHOLD} failures",
            )
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다")

    if user.status != "active":
        await _write_audit_log(
            db, actor=form_data.username, action="login_failure",
            request=request, detail="inactive account",
        )
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다")

    user.last_login_at = datetime.utcnow()
    await db.commit()
    _reset_login_counter(key)

    token = create_access_token({"sub": user.name, "role": _infer_user_role(user)})
    await _write_audit_log(
        db, actor=user.name, action="login_success", request=request,
        detail=f"role={_infer_user_role(user)}",
    )
    return TokenResponse(access_token=token)


@router.post("/register", status_code=201)
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="이미 사용 중인 이메일입니다")

    new_user = User(
        name=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(new_user)
    await db.commit()
    await _write_audit_log(
        db, actor=body.username, action="register", request=request,
        detail=f"email={body.email}",
    )
    return {"message": "회원가입이 완료되었습니다"}


@router.get("/me", response_model=UserInfo)
async def me(user: UserInfo = Depends(get_current_user)):
    return user
