"""
[R3] Defense Proxy — 5레이어 방어 Proxy 서버

기능별 파이프라인 섹션 4 참조.
Layer 1: 입력 필터 → Layer 2: 시스템 프롬프트 주입 → Layer 3: 타겟 호출
→ Layer 4: 출력 필터 → Layer 5: Execution Guard (LLM06)

⚠️ 모든 엔드포인트에 JWT 인증 필수 (R7의 auth 모듈 사용)
"""

from fastapi import FastAPI

app = FastAPI(title="AgentShield Defense Proxy")

# TODO: [R3] 구현
# - POST /proxy/{session_id}/register — 방어 규칙 등록 (JWT 인증 필요)
# - POST /proxy/{session_id}/chat — Proxy 경유 챗봇
# - DELETE /proxy/{session_id}/rules — 방어 규칙 해제
