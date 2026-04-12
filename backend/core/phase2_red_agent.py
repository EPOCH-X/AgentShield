"""
[R1] Phase 2 — Red Agent 변형 공격

세부기획서 섹션 1(R1 역할), 기능별 파이프라인 섹션 2 참조.
Phase 1에서 "safe" 결과를 가져와 AI가 우회 변형 생성. 최대 10라운드 Self-Play.
"""

# TODO: [R1] 구현
# 의존: [R2] Phase 1 완료, [R4] ChromaDB + llm_client, [R1] judge.py
# 입력: session_id, target_url, Phase 1의 "safe" 결과
# 출력: test_results에 phase=2, judgment="vulnerable" 추가
