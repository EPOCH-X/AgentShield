from __future__ import annotations

import asyncio
import json
from collections import Counter, defaultdict
from pathlib import Path

from sqlalchemy import select

from backend.data_cleaning.cleaning_rules import (
    VALID_TRAINING_JUDGMENTS,
    split_clean_records,
    summarize_exclusion_reasons,
)
from backend.database import async_session
from backend.models.test_result import TestResult
from backend.models.test_session import TestSession

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
AUDIT_JSON = RESULTS_DIR / "training_exclusion_audit_latest.json"
AUDIT_JSONL = RESULTS_DIR / "training_exclusion_rows_latest.jsonl"


async def _load_rows() -> tuple[list[dict], dict[str, dict]]:
    async with async_session() as db:
        session_rows = (await db.execute(select(TestSession))).scalars().all()
        result_rows = (await db.execute(select(TestResult))).scalars().all()

    session_map = {
        str(session.id): {
            "session_id": str(session.id),
            "project_name": session.project_name,
            "target_api_url": session.target_api_url,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        }
        for session in session_rows
    }

    rows = []
    for row in result_rows:
        rows.append({
            "id": row.id,
            "session_id": str(row.session_id),
            "phase": row.phase,
            "seed_id": row.seed_id or "",
            "round": row.round,
            "attack_prompt": row.attack_prompt or "",
            "target_response": row.target_response or "",
            "judgment": row.judgment or "",
            "judgment_layer": row.judgment_layer,
            "category": row.category or "",
            "subcategory": row.subcategory or "",
            "detail": row.detail or "",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })

    return rows, session_map


def _build_audit_payload(excluded_rows: list[dict], session_map: dict[str, dict]) -> dict:
    session_stats: dict[str, dict] = defaultdict(lambda: {
        "excluded_rows": 0,
        "reasons": Counter(),
        "row_ids": [],
    })

    for row in excluded_rows:
        session_id = row["session_id"]
        stats = session_stats[session_id]
        stats["excluded_rows"] += 1
        stats["reasons"].update(row.get("exclusion_reasons") or [])
        stats["row_ids"].append(row["id"])

    impacted_sessions = []
    for session_id, stats in sorted(session_stats.items(), key=lambda item: item[1]["excluded_rows"], reverse=True):
        meta = session_map.get(session_id, {"session_id": session_id})
        impacted_sessions.append({
            **meta,
            "excluded_rows": stats["excluded_rows"],
            "reasons": dict(sorted(stats["reasons"].items())),
            "row_ids": stats["row_ids"],
        })

    return {
        "summary": {
            "impacted_session_count": len(impacted_sessions),
            "excluded_row_count": len(excluded_rows),
            "exclusion_reasons": summarize_exclusion_reasons(excluded_rows),
        },
        "impacted_sessions": impacted_sessions,
    }


async def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    rows, session_map = await _load_rows()
    clean_rows, excluded_rows = split_clean_records(rows, allowed_judgments=VALID_TRAINING_JUDGMENTS)
    payload = _build_audit_payload(excluded_rows, session_map)

    with open(AUDIT_JSON, "w", encoding="utf-8") as file_obj:
        json.dump(payload, file_obj, ensure_ascii=False, indent=2)

    with open(AUDIT_JSONL, "w", encoding="utf-8") as file_obj:
        for row in excluded_rows:
            file_obj.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"원본 행 수: {len(rows)}")
    print(f"정제 후 학습 가능 행 수: {len(clean_rows)}")
    print(f"학습 제외 행 수: {len(excluded_rows)}")
    print(f"제외 사유: {payload['summary']['exclusion_reasons']}")
    print(f"오염 세션 목록: {AUDIT_JSON}")
    print(f"학습 제외 행 목록: {AUDIT_JSONL}")


if __name__ == "__main__":
    asyncio.run(main())