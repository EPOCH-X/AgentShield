"""
scripts/ingest_testbed_kb.py
testbed KB 문서를 ChromaDB에 적재하는 스크립트

실행 방법:
  python scripts/ingest_testbed_kb.py
  python scripts/ingest_testbed_kb.py --persist-path ./chromadb_data

컬렉션:
  kb_public_docs      ← data/testbed_kb/public/
  kb_internal_runbooks ← data/testbed_kb/internal/
  kb_poisoned_docs    ← data/testbed_kb/poisoned/
"""

import argparse
import os
import uuid
from pathlib import Path

# ── ChromaDB ──
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

# ── 임베딩 (기존 프로젝트와 동일: all-MiniLM-L6-v2) ──
from sentence_transformers import SentenceTransformer


class MiniLMEmbeddingFunction(EmbeddingFunction):
    """기존 backend/rag/embedder.py와 동일한 임베딩 함수"""
    def __init__(self):
        self.model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

    def __call__(self, input: Documents) -> Embeddings:
        return self.model.encode(input).tolist()


# ── KB 폴더 → ChromaDB 컬렉션 매핑 ──
COLLECTION_MAP = {
    "public":   "kb_public_docs",
    "internal": "kb_internal_runbooks",
    "poisoned": "kb_poisoned_docs",
}

DEFAULT_PERSIST_PATH = "./chromadb_data"
KB_BASE_PATH = Path("data/testbed_kb")


def load_documents(folder: str) -> list[dict]:
    """
    지정 폴더의 .md 파일을 모두 읽어서 반환
    반환 형식: [{"filename": "faq.md", "content": "...", "folder": "public"}, ...]
    """
    folder_path = KB_BASE_PATH / folder
    docs = []

    for md_file in sorted(folder_path.glob("*.md")):
        content = md_file.read_text(encoding="utf-8").strip()
        if content:
            docs.append({
                "filename": md_file.name,
                "content": content,
                "folder": folder,
            })
            print(f"  읽음: {md_file.name} ({len(content)}자)")

    return docs


def ingest(persist_path: str):
    print(f"[ingest] ChromaDB 경로: {persist_path}")
    embed_fn = MiniLMEmbeddingFunction()
    client = chromadb.PersistentClient(path=os.path.abspath(persist_path))

    for folder, collection_name in COLLECTION_MAP.items():
        print(f"\n[ingest] {folder}/ → {collection_name}")

        # 기존 컬렉션 초기화 (재실행 안전)
        try:
            client.delete_collection(collection_name)
            print(f"  기존 컬렉션 삭제: {collection_name}")
        except Exception:
            pass

        collection = client.get_or_create_collection(
            name=collection_name,
            embedding_function=embed_fn,
            metadata={"hnsw:space": "cosine"},
        )

        # 문서 로드
        docs = load_documents(folder)
        if not docs:
            print(f"  경고: {folder}/ 에 .md 파일 없음, 건너뜀")
            continue

        # ChromaDB에 적재
        collection.add(
            ids=[str(uuid.uuid4()) for _ in docs],
            documents=[d["content"] for d in docs],
            metadatas=[
                {
                    "filename": d["filename"],
                    "folder": d["folder"],
                    "collection": collection_name,
                    # poisoned 문서는 명시적으로 태깅 (탐지 결과 추적용)
                    "is_poisoned": str(d["folder"] == "poisoned"),
                }
                for d in docs
            ],
        )
        print(f"  → {len(docs)}개 문서 적재 완료")

    print("\n[ingest] 완료!")
    print("컬렉션 요약:")
    for collection_name in COLLECTION_MAP.values():
        col = client.get_collection(collection_name, embedding_function=embed_fn)
        print(f"  {collection_name}: {col.count()}개")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="testbed KB → ChromaDB 적재")
    parser.add_argument(
        "--persist-path",
        default=DEFAULT_PERSIST_PATH,
        help="ChromaDB 저장 경로 (기본값: ./chromadb_data)",
    )
    args = parser.parse_args()
    ingest(args.persist_path)