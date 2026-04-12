"""
[R5] Monitoring Proxy — 직원 AI 사용 모니터링

기능별 파이프라인 섹션 9, 세부기획서 섹션 7 참조.
P1 기밀유출 → P2 부적절사용 → P3 Rate Limit → Forward → 출력 스캔 → 로그 → 제재
"""

from fastapi import FastAPI

app = FastAPI(title="AgentShield Monitoring Proxy")

# TODO: [R5] 구현
# - POST /monitor/chat — 모니터링 경유 챗봇 (JWT 인증 필요)
# - check_confidential(), check_inappropriate(), is_rate_limited()
# - check_escalation() — 위반 횟수 → 제재 에스컬레이션
