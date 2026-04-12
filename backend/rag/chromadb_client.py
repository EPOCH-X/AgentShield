"""
[R4] ChromaDB 클라이언트 — RAG 검색/저장

기능별 파이프라인 섹션 6 참조.
defense_patterns, attack_results 2개 컬렉션 운영.
cosine metric (hnsw:space=cosine) 사용.
"""

# TODO: [R4] 구현
# - get_or_create_collection() with cosine metric
# - search_defense(), search_attacks(), add_attack()
# - 중복 체크: 코사인 거리 < 0.3 (유사도 > 0.7) 시 저장 안 함
