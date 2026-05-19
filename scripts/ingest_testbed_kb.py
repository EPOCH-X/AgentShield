"""ChromaDB에 testbed_kb 문서를 적재한다.

`data/testbed_kb/*.md` (평탄 구조) 의 frontmatter `audience` / `sensitivity` 값을
기준으로 다음 3개 컬렉션에 자동 분류해 적재한다 — testbed의
`tool_gateway.internal_api._kb_search` 가 이 컬렉션들을 검색한다.

- kb_public_docs        : audience=customer (고객 대면 정책)
- kb_internal_runbooks  : audience=internal (컴플라이언스/내부 절차)
- kb_poisoned_docs      : audience=operations 또는 sensitivity=confidential
                          (indirect injection 표면용 내부 운영 핸드북)

사용법:
  python scripts/ingest_testbed_kb.py
  docker compose -f docker-compose.testbed.yml run --rm kb_ingest

환경변수:
  TESTBED_CHROMADB_HOST  (기본: localhost)
  TESTBED_CHROMADB_PORT  (기본: 8005)
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

import chromadb


CHROMA_HOST = os.getenv("TESTBED_CHROMADB_HOST", "localhost")
CHROMA_PORT = int(os.getenv("TESTBED_CHROMADB_PORT", 8005))

KB_ROOT = Path(__file__).resolve().parent.parent / "data" / "testbed_kb"

COLLECTIONS = ("kb_public_docs", "kb_internal_runbooks", "kb_poisoned_docs")

# Markdown body chunk 최대 글자수. 너무 짧으면 컨텍스트 부족, 너무 크면 검색 정확도↓.
CHUNK_MAX_CHARS = 1200
CHUNK_OVERLAP = 120

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """YAML frontmatter(단순 key: value) 파싱 + 본문 분리."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip().strip("\"'")
    body = text[match.end():]
    return meta, body


def _classify_collection(meta: dict[str, str]) -> str:
    """audience/sensitivity 조합 → 컬렉션 이름."""
    audience = (meta.get("audience") or "customer").strip().lower()
    sensitivity = (meta.get("sensitivity") or "public").strip().lower()
    if sensitivity == "confidential" or audience == "operations":
        return "kb_poisoned_docs"
    if audience == "internal":
        return "kb_internal_runbooks"
    return "kb_public_docs"


def _chunk_body(body: str) -> list[str]:
    """단순 문단/구분 기준 청크 분할. 마크다운 헤딩(#) 단위를 우선 시도하고,
    너무 큰 섹션은 CHUNK_MAX_CHARS 기준으로 한 번 더 자른다."""
    text = body.strip()
    if not text:
        return []
    # 1) ##/### 같은 헤딩 또는 빈 줄 두 번 기준으로 큰 단위 분할
    sections: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("## ") and buf:
            sections.append("\n".join(buf).strip())
            buf = [line]
        else:
            buf.append(line)
    if buf:
        sections.append("\n".join(buf).strip())

    # 2) 큰 섹션은 CHUNK_MAX_CHARS 기준으로 한 번 더 분할 (overlap 포함)
    chunks: list[str] = []
    for section in sections:
        if not section:
            continue
        if len(section) <= CHUNK_MAX_CHARS:
            chunks.append(section)
            continue
        start = 0
        while start < len(section):
            end = min(len(section), start + CHUNK_MAX_CHARS)
            chunks.append(section[start:end].strip())
            if end == len(section):
                break
            start = max(0, end - CHUNK_OVERLAP)
    return [c for c in chunks if c]


def _load_documents() -> list[dict[str, Any]]:
    """`data/testbed_kb/*.md` 전체 로드 → 컬렉션별 청크 리스트."""
    if not KB_ROOT.exists():
        print(f"[ingest_testbed_kb] KB 디렉토리가 없습니다: {KB_ROOT}")
        return []

    bucket: dict[str, list[dict[str, Any]]] = {name: [] for name in COLLECTIONS}

    for md_file in sorted(KB_ROOT.glob("*.md")):
        if md_file.name.lower() == "readme.md":
            continue
        text = md_file.read_text(encoding="utf-8")
        meta, body = _parse_frontmatter(text)

        collection = _classify_collection(meta)
        chunks = _chunk_body(body)
        if not chunks:
            print(f"  [skip] {md_file.name} — 본문 없음")
            continue

        base_id = md_file.stem
        title = meta.get("title") or base_id
        audience = (meta.get("audience") or "customer").strip().lower()
        sensitivity = (meta.get("sensitivity") or "public").strip().lower()
        last_updated = meta.get("last_updated") or ""

        for idx, chunk in enumerate(chunks):
            bucket[collection].append({
                "id": f"{base_id}#{idx:02d}",
                "document": chunk,
                "metadata": {
                    "source": md_file.name,
                    "title": title,
                    "audience": audience,
                    "sensitivity": sensitivity,
                    "last_updated": last_updated,
                    "chunk_index": idx,
                    "chunk_total": len(chunks),
                },
            })

    return [
        {"collection": name, "items": bucket[name]}
        for name in COLLECTIONS
    ]


def main() -> int:
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    except Exception as exc:
        print(f"[ingest_testbed_kb] ChromaDB 연결 실패: {exc}")
        return 2

    print(f"ChromaDB 연결: {CHROMA_HOST}:{CHROMA_PORT}")

    buckets = _load_documents()
    if not buckets:
        return 1

    total_loaded = 0
    for entry in buckets:
        name = entry["collection"]
        items = entry["items"]

        # idempotent: 기존 컬렉션 비우고 재생성
        try:
            client.delete_collection(name)
        except Exception:
            pass
        col = client.create_collection(name)

        if not items:
            print(f"  [{name}] 문서 없음 — 빈 컬렉션 생성")
            continue

        col.add(
            ids=[item["id"] for item in items],
            documents=[item["document"] for item in items],
            metadatas=[item["metadata"] for item in items],
        )
        sources = sorted({item["metadata"]["source"] for item in items})
        print(f"  [{name}] {len(items)}개 청크 적재 (원본 {len(sources)}개: {', '.join(sources)})")
        total_loaded += len(items)

    print(f"ingest 완료. 총 {total_loaded}개 청크.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
