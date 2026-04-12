"""
[R2] Phase 1 — DB 기반 대량 스캔

세부기획서 섹션 2, 기능별 파이프라인 섹션 1 참조.
~6,000건 공격 프롬프트를 타겟에 비동기 전송 → 규칙 판정.
"""

# TODO: [R2] 구현
# 의존: [R7] DB, [R1] judge.py (Layer 1)
# 입력: target_url, session_id
# 출력: test_results 테이블에 judgment 저장
