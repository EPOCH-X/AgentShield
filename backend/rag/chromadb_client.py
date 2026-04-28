"""
[R4] ChromaDB 클라이언트 — RAG 검색/저장

기능별 파이프라인 섹션 6 참조.
defense_patterns, attack_results 2개 컬렉션 운영.
cosine metric (hnsw:space=cosine) 사용.
"""

# TODO: [R4] 구현
# - get_or_create_collection() with cosine metric
# - search_defense(), search_attacks(), add_attack()
# - 중복 체크: 코사인 거리 < 0.1 (유사도 > 0.90) 시 저장 안 함
#   → 보안 레드팀에서는 미세한 프레이밍 차이가 핵심이므로 거의 동일 문장만 제외

import uuid
from datetime import datetime
from typing import Optional
from backend.config import settings

try:
    import chromadb
    _CHROMADB_IMPORT_ERROR = None
except Exception as exc:
    chromadb = None
    _CHROMADB_IMPORT_ERROR = str(exc)

class ChromaRAGClient:
    def __init__(self):
        if chromadb is None:
            raise RuntimeError(f"chromadb import failed: {_CHROMADB_IMPORT_ERROR}")

        from backend.rag.embedder import MiniLMEmbeddingFunction

        import os
        persist_dir = os.path.abspath(settings.CHROMADB_PERSIST_PATH)
        os.makedirs(persist_dir, exist_ok=True)

        # 로컬 PersistentClient (Docker 불필요)
        self.client = chromadb.PersistentClient(path=persist_dir)

        self.embed_fn = MiniLMEmbeddingFunction()

        # 컬렉션 초기화 — 기존 컬렉션이 default embedding으로 생성된 경우
        # embedding_function 충돌 방지: 기존 컬렉션 삭제 후 재생성
        for col_name in ("defense_patterns", "attack_results"):
            try:
                self.client.get_or_create_collection(
                    name=col_name,
                    embedding_function=self.embed_fn,
                    metadata={"hnsw:space": "cosine"},
                )
            except ValueError:
                # Embedding function conflict — 기존 컬렉션이 다른 embedding으로 생성됨
                self.client.delete_collection(col_name)
                self.client.get_or_create_collection(
                    name=col_name,
                    embedding_function=self.embed_fn,
                    metadata={"hnsw:space": "cosine"},
                )

        self.defense_col = self.client.get_collection(
            name="defense_patterns",
            embedding_function=self.embed_fn,
        )
        self.attack_col = self.client.get_collection(
            name="attack_results",
            embedding_function=self.embed_fn,
        )
    
    def search_defense(self, query: str, n_results: int = 3, category: str | None = None):
        """Phase 3: 방어 패턴(Blue Agent용) 검색"""
        kwargs = {
            "query_texts": [query],
            "n_results": n_results,
        }
        if category:
            kwargs["where"] = {"category": category}
        return self.defense_col.query(**kwargs)
    
    def search_attacks(self, query: str, n_results: int = 3, where: Optional[dict] = None):
        """Phase 2: 기존 성공한 공격(Red Agent용) 검색"""
        return self.attack_col.query(
            query_texts=[query],
            n_results=n_results,
            where=where,
        )

    def get_recent_attacks(self, limit: int = 3, where: Optional[dict] = None):
        """최근 저장된 성공 공격을 메타데이터 필터와 함께 가져온다."""
        return self.attack_col.get(
            where=where,
            include=["metadatas", "documents"],
        )
    
    def add_attack(self, attack_prompt: str, metadata: dict) -> bool:
        """Phase 2: 공격 성공 시 호출. 중복 체크 후 저장"""
        seed_id = metadata.get("seed_id")
        if seed_id and (self.attack_col.get(where={"seed_id": seed_id}).get("ids") or []):
            print(f"동일 seed_id 공격 패턴 존재 ({seed_id}). 저장을 생략합니다.")
            return False

        # 가장 비슷한 공격 1개 검색
        results = self.search_attacks(query=attack_prompt, n_results=1)
        
        # 중복 체크: 거리가 0.3 미만이면 저장 안 함 (유사도 > 0.7)
        if results['distances'] and len(results['distances'][0]) > 0:
            distance = results['distances'][0][0]
            similarity = 1 - distance

            if similarity > 0.90:
                print(f"거의 동일한 공격 패턴 존재 (유사도: {similarity:.4f}). 저장을 생략합니다.")
                return False

        # 새로운 공격 패턴 저장
        doc_id = str(uuid.uuid4())
        metadata = {
            **metadata,
            "created_at": metadata.get("created_at") or datetime.utcnow().isoformat(),
        }
        self.attack_col.add(
            ids=[doc_id],
            documents=[attack_prompt],
            metadatas=[metadata]
        )
        print(f"신규 공격 패턴 저장 완료 (ID: {doc_id})")
        return True


_rag_client: Optional[ChromaRAGClient] = None
_rag_init_error: Optional[str] = None


def get_rag_client() -> ChromaRAGClient:
    """ChromaDB 클라이언트를 지연 초기화한다.

    import 시점에 ChromaDB 서버가 내려가 있어도 전체 파이프라인이 죽지 않도록,
    실제 사용 시점에만 연결을 시도한다.
    """
    global _rag_client, _rag_init_error

    if _rag_client is not None:
        return _rag_client

    try:
        _rag_client = ChromaRAGClient()
        _rag_init_error = None
        return _rag_client
    except Exception as exc:
        _rag_init_error = str(exc)
        raise RuntimeError(
            f"ChromaDB initialization failed (persist={settings.CHROMADB_PERSIST_PATH}): {exc}"
        ) from exc


def get_rag_status() -> dict:
    """RAG 연결 상태를 반환한다."""
    try:
        get_rag_client()
        return {
            "available": True,
            "persist_path": settings.CHROMADB_PERSIST_PATH,
            "error": None,
        }
    except RuntimeError as exc:
        return {
            "available": False,
            "persist_path": settings.CHROMADB_PERSIST_PATH,
            "error": str(exc),
        }


def _flatten_query_results(results: dict) -> list[dict]:
    """Chroma query 결과를 호출부가 쓰기 쉬운 list 형태로 변환한다."""
    documents = results.get("documents") or [[]]
    metadatas = results.get("metadatas") or [[]]
    distances = results.get("distances") or [[]]
    ids = results.get("ids") or [[]]

    flat = []
    for index, document in enumerate(documents[0] if documents else []):
        metadata = metadatas[0][index] if metadatas and metadatas[0] and index < len(metadatas[0]) else {}
        distance = distances[0][index] if distances and distances[0] and index < len(distances[0]) else None
        doc_id = ids[0][index] if ids and ids[0] and index < len(ids[0]) else None
        flat.append({
            "id": doc_id,
            "document": document,
            "metadata": metadata or {},
            "distance": distance,
            "similarity": (1 - distance) if distance is not None else None,
            "attack_prompt": document,
        })
    return flat


def _flatten_get_results(results: dict) -> list[dict]:
    """Chroma get 결과를 호출부가 쓰기 쉬운 list 형태로 변환한다."""
    documents = results.get("documents") or []
    metadatas = results.get("metadatas") or []
    ids = results.get("ids") or []

    flat = []
    for index, document in enumerate(documents):
        metadata = metadatas[index] if index < len(metadatas) else {}
        doc_id = ids[index] if index < len(ids) else None
        flat.append({
            "id": doc_id,
            "document": document,
            "metadata": metadata or {},
            "distance": None,
            "similarity": None,
            "attack_prompt": document,
        })
    return flat


def search_defense(query: str, n_results: int = 3) -> list[dict]:
    """방어 패턴 검색 래퍼."""
    try:
        client = get_rag_client()
        return _flatten_query_results(client.search_defense(query=query, n_results=n_results))
    except Exception as exc:
        print(f"ChromaDB defense search unavailable: {exc}")
        return []


def search_attacks(query: str, n_results: int = 3, where: Optional[dict] = None) -> list[dict]:
    """성공 공격 검색 래퍼."""
    try:
        client = get_rag_client()
        return _flatten_query_results(client.search_attacks(query=query, n_results=n_results, where=where))
    except Exception as exc:
        print(f"ChromaDB attack search unavailable: {exc}")
        return []


def get_recent_attacks(limit: int = 3, where: Optional[dict] = None) -> list[dict]:
    """최근 성공 공격 조회 래퍼."""
    try:
        client = get_rag_client()
        results = client.get_recent_attacks(limit=limit, where=where)
        flat = _flatten_get_results(results)

        def _sort_key(item: dict) -> tuple[int, str, str]:
            created_at = (item.get("metadata") or {}).get("created_at") or ""
            return (1 if created_at else 0, created_at, item.get("id") or "")

        flat.sort(key=_sort_key)
        return flat[-limit:] if limit > 0 else flat
    except Exception as exc:
        print(f"ChromaDB recent attack lookup unavailable: {exc}")
        return []


def list_attack_entries(limit: int = 20, where: Optional[dict] = None) -> list[dict]:
    """attack_results 컬렉션의 문서를 최근순 preview 형태로 반환한다."""
    try:
        client = get_rag_client()
        results = client.attack_col.get(where=where, include=["metadatas", "documents"])
        flat = _flatten_get_results(results)

        def _sort_key(item: dict) -> tuple[int, str, str]:
            created_at = (item.get("metadata") or {}).get("created_at") or ""
            return (1 if created_at else 0, created_at, item.get("id") or "")

        flat.sort(key=_sort_key, reverse=True)
        return flat[:limit] if limit > 0 else flat
    except Exception as exc:
        print(f"ChromaDB attack listing unavailable: {exc}")
        return []


def delete_attack_entries(ids: Optional[list[str]] = None, seed_ids: Optional[list[str]] = None) -> dict:
    """attack_results 컬렉션에서 id 또는 seed_id 기준으로 문서를 삭제한다."""
    ids = [item for item in (ids or []) if item]
    seed_ids = [item for item in (seed_ids or []) if item]
    if not ids and not seed_ids:
        return {"deleted": 0, "ids": []}

    try:
        client = get_rag_client()
        delete_ids = list(ids)

        if seed_ids:
            all_data = client.attack_col.get(include=["metadatas"])
            all_ids = all_data.get("ids") or []
            metadatas = all_data.get("metadatas") or []
            for index, doc_id in enumerate(all_ids):
                metadata = metadatas[index] if index < len(metadatas) else {}
                if (metadata or {}).get("seed_id") in seed_ids:
                    delete_ids.append(doc_id)

        delete_ids = list(dict.fromkeys(delete_ids))
        if not delete_ids:
            return {"deleted": 0, "ids": []}

        client.attack_col.delete(ids=delete_ids)
        return {"deleted": len(delete_ids), "ids": delete_ids}
    except Exception as exc:
        print(f"ChromaDB attack delete unavailable: {exc}")
        return {"deleted": 0, "ids": [], "error": str(exc)}


def add_attack(attack_prompt: Optional[str] = None, metadata: Optional[dict] = None, **kwargs) -> bool:
    """성공 공격 저장 래퍼.

    기존 코드 호환을 위해 `attack_prompt` + `metadata` 형태와,
    `attack=...`, `category=...` 같은 keyword 인자 형태를 모두 지원한다.
    """
    prompt = attack_prompt or kwargs.pop("attack", None)
    if not prompt:
        raise ValueError("attack_prompt or attack is required")

    merged_metadata = dict(metadata or {})
    merged_metadata.update(kwargs)

    try:
        client = get_rag_client()
        return client.add_attack(prompt, merged_metadata)
    except Exception as exc:
        print(f"ChromaDB add_attack unavailable: {exc}")
        return False


class _RAGClientProxy:
    """기존 `rag_client.search_defense()` 호출부 호환용 프록시."""

    def __getattr__(self, name: str):
        client = get_rag_client()
        return getattr(client, name)


# ── ChromaDB 오염 정리 유틸리티 ──────────────────────────────────

def audit_attack_results(dry_run: bool = True) -> dict:
    """attack_results 컬렉션에서 FP 의심 데이터를 감사한다.

    저장된 각 공격의 target_response를 refusal/meta-analysis 패턴으로 재검증.
    dry_run=True면 목록만 반환, False면 실제 삭제.

    Returns:
        {"total": int, "suspects": [...], "deleted": int}
    """
    from backend.core.judge import _has_refusal, _has_meta_analysis

    client = get_rag_client()
    all_data = client.attack_col.get(include=["metadatas", "documents"])
    ids = all_data.get("ids", [])
    metadatas = all_data.get("metadatas", [])
    documents = all_data.get("documents", [])

    suspects = []
    for i, doc_id in enumerate(ids):
        meta = metadatas[i] if i < len(metadatas) else {}
        doc = documents[i] if i < len(documents) else ""
        resp = meta.get("target_response", "")

        signals = []
        if _has_refusal(resp):
            signals.append("refusal")
        if _has_meta_analysis(resp):
            signals.append("meta_analysis")

        if signals:
            suspects.append({
                "id": doc_id,
                "category": meta.get("category", "?"),
                "source": meta.get("source", "?"),
                "signals": signals,
                "attack_excerpt": doc[:100] if doc else "",
                "response_excerpt": resp[:100] if resp else "",
            })

    deleted = 0
    if not dry_run and suspects:
        delete_ids = [s["id"] for s in suspects]
        client.attack_col.delete(ids=delete_ids)
        deleted = len(delete_ids)

    return {"total": len(ids), "suspects": suspects, "deleted": deleted}


rag_client = _RAGClientProxy()


def get_attack_category_counts() -> dict[str, int]:
    """attack_results 컬렉션의 카테고리별 저장 건수를 반환한다."""
    try:
        client = get_rag_client()
        all_data = client.attack_col.get(include=["metadatas"])
    except Exception:
        return {}

    counts: dict[str, int] = {}
    for metadata in all_data.get("metadatas") or []:
        category = (metadata or {}).get("category", "unknown")
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))