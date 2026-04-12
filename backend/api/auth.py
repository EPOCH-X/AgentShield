"""
[R7] 인증 API — JWT 토큰 발급/검증
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

from backend.config import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    username: str
    role: str  # admin / auditor / user


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


@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # TODO: 실제 사용자 DB 검증으로 교체
    # 현재는 개발용 하드코딩 (반드시 교체 필요)
    if form_data.username == "admin" and form_data.password == "admin":
        token = create_access_token({"sub": form_data.username, "role": "admin"})
        return TokenResponse(access_token=token)
    raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다")


@router.get("/me", response_model=UserInfo)
async def me(user: UserInfo = Depends(get_current_user)):
    return user
