"""
ChromaDB에 testbed_kb 문서를 적재한다.

사용법:
  python scripts/ingest_testbed_kb.py

환경변수:
  TESTBED_CHROMADB_HOST  (기본: localhost)
  TESTBED_CHROMADB_PORT  (기본: 8005)
"""

import os
import sys
from pathlib import Path

import chromadb

CHROMA_HOST = os.getenv("TESTBED_CHROMADB_HOST", "localhost")
CHROMA_PORT = int(os.getenv("TESTBED_CHROMADB_PORT", 8005))

KB_ROOT = Path(__file__).parent.parent / "data" / "testbed_kb"

COLLECTION_MAP = {
    "public": "kb_public_docs",
    "internal": "kb_internal_runbooks",
    "poisoned": "kb_poisoned_docs",
}


def load_docs(subdir: str) -> list[dict]:
    docs = []
    folder = KB_ROOT / subdir
    for md_file in sorted(folder.glob("*.md")):
        text = md_file.read_text(encoding="utf-8")

        # frontmatter에서 메타데이터 추출
        meta = {"filename": md_file.name, "category": subdir}
        if text.startswith("---"):
            lines = text.split("\n")
            for line in lines[1:]:
                if line.strip() == "---":
                    break
                if ": " in line:
                    k, v = line.split(": ", 1)
                    meta[k.strip()] = v.strip()

        docs.append({"id": meta.get("doc_id", md_file.stem), "content": text, "meta": meta})
    return docs


def ingest():
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    print(f"ChromaDB 연결: {CHROMA_HOST}:{CHROMA_PORT}")

    for subdir, collection_name in COLLECTION_MAP.items():
        docs = load_docs(subdir)
        if not docs:
            print(f"  [{subdir}] 문서 없음, 스킵")
            continue

        # 기존 컬렉션 초기화 후 재생성
        try:
            client.delete_collection(collection_name)
        except Exception:
            pass
        col = client.create_collection(collection_name)

        col.add(
            ids=[d["id"] for d in docs],
            documents=[d["content"] for d in docs],
            metadatas=[d["meta"] for d in docs],
        )
        print(f"  [{collection_name}] {len(docs)}개 문서 적재 완료")

    print("ingest 완료.")


if __name__ == "__main__":
    ingest()
