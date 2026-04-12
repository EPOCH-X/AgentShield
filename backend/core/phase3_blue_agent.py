"""
[R3] Phase 3 — Blue Agent 방어 코드 생성

기능별 파이프라인 섹션 3, 세부기획서 섹션 5 참조.
Phase 1+2의 모든 취약점에 대해 방어 코드 3종 자동 생성.
생성된 코드는 초안이며, 반드시 사람 검수(R1+R3)를 거쳐야 한다.
"""

# TODO: [R3] 구현
# 의존: [R2+R1] Phase 1+2 완료, [R4] ChromaDB defense_patterns + llm_client
# 입력: session_id, 모든 "vulnerable" 결과
# 출력: defense_code 필드 업데이트 (defense_reviewed=False)
