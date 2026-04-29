#!/usr/bin/env python3
"""Check ChromaDB connectivity without forcing embedding model downloads."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings  # noqa: E402


def _raw_client():
    import chromadb

    if settings.CHROMADB_MODE == "http":
        return chromadb.HttpClient(host=settings.CHROMADB_HOST, port=settings.CHROMADB_PORT)
    if settings.CHROMADB_MODE == "persistent":
        return chromadb.PersistentClient(path=settings.CHROMADB_PERSIST_PATH)
    raise ValueError("CHROMADB_MODE must be 'persistent' or 'http'")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full-rag-client",
        action="store_true",
        help="Initialize backend.rag.chromadb_client, including embedding function.",
    )
    args = parser.parse_args()

    if args.full_rag_client:
        from backend.rag.chromadb_client import get_rag_client, get_rag_status

        status = get_rag_status()
        print(f"[ChromaDB] status={status}", flush=True)
        if not status.get("available"):
            return 2
        client = get_rag_client().client
    else:
        print(
            {
                "mode": settings.CHROMADB_MODE,
                "host": settings.CHROMADB_HOST if settings.CHROMADB_MODE == "http" else None,
                "port": settings.CHROMADB_PORT if settings.CHROMADB_MODE == "http" else None,
                "persist_path": settings.CHROMADB_PERSIST_PATH,
            },
            flush=True,
        )
        client = _raw_client()

    collections = sorted(col.name for col in client.list_collections())
    print(f"[ChromaDB] collections={collections}", flush=True)

    required = {"attack_results", "defense_patterns"}
    missing = sorted(required - set(collections))
    if missing:
        print(f"[ChromaDB] missing_collections={missing}", flush=True)
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
