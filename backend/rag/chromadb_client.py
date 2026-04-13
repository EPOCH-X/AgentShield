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

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import uuid
import chromadb
from backend.config import settings
from backend.rag.embedder import MiniLMEmbeddingFunction

class ChromaRAGClient:
    def __init__(self):
        # HTTP 클라이언트 연결
        self.client = chromadb.HttpClient(
            host=settings.CHROMADB_HOST, 
            port=settings.CHROMADB_PORT
        )

        self.embed_fn = MiniLMEmbeddingFunction()

        # 컬렉션 초기화
        self.defense_col = self.client.get_or_create_collection(
            name="defense_patterns",
            embedding_function=self.embed_fn,
            metadata={"hnsw:space": "cosine"}
        )

        self.attack_col = self.client.get_or_create_collection(
            name="attack_results",
            embedding_function=self.embed_fn,
            metadata={"hnsw:space": "cosine"}
        )
    
    def search_defense(self, query: str, n_results: int = 3):
        """Phase 3: 방어 패턴(Blue Agent용) 검색"""
        return self.defense_col.query(
            query_texts=[query],
            n_results=n_results
        )
    
    def search_attacks(self, query: str, n_results: int = 3):
        """Phase 2: 기존 성공한 공격(Red Agent용) 검색"""
        return self.attack_col.query(
            query_texts=[query],
            n_results=n_results
        )
    
    def add_attack(self, attack_prompt: str, metadata: dict) -> bool:
        """Phase 2: 공격 성공 시 호출. 중복 체크 후 저장"""
        # 가장 비슷한 공격 1개 검색
        results = self.search_attacks(query=attack_prompt, n_results=1)
        
        # 중복 체크: 거리가 0.3 미만이면 저장 안 함 (유사도 > 0.7)
        if results['distances'] and len(results['distances'][0]) > 0:
            distance = results['distances'][0][0]
            similarity = 1 - distance
            
            if similarity > 0.7: 
                print(f"유사한 공격 패턴 존재 (유사도: {similarity:.4f}). 저장을 생략합니다.")
                return False

        # 새로운 공격 패턴 저장
        doc_id = str(uuid.uuid4())
        self.attack_col.add(
            ids=[doc_id],
            documents=[attack_prompt],
            metadatas=[metadata]
        )
        print(f"신규 공격 패턴 저장 완료 (ID: {doc_id})")
        return True
    
# 외부에서 재사용할 싱글톤 인스턴스
rag_client = ChromaRAGClient()