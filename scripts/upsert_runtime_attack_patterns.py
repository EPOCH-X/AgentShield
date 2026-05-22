#!/usr/bin/env python3
"""Upsert runtime Phase1 attack patterns without deleting referenced rows.

Unlike ``ingest_attack_patterns.py --replace-source``, this script updates the
existing row for each ``(source, category)``. That preserves historical
``test_results.attack_pattern_id`` foreign keys while replacing the active seed
prompt used by new scans.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
from typing import Any

from sqlalchemy import select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database import async_session  # noqa: E402
from backend.models.attack_pattern import AttackPattern  # noqa: E402


def _load_patterns(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("runtime attack pattern file must be a JSON list")
    rows: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip().upper()
        prompt = str(item.get("attack_prompt") or item.get("prompt_text") or "").strip()
        if not category or not prompt:
            continue
        rows.append({
            "category": category,
            "subcategory": str(item.get("subcategory") or "").strip() or None,
            "severity": str(item.get("severity") or "medium").strip().lower(),
            "prompt_text": prompt,
        })
    if not rows:
        raise ValueError("no valid runtime attack patterns found")
    return rows


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--source", default="accepted_one_per_category")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    patterns = _load_patterns(path)

    updated = 0
    inserted = 0
    async with async_session() as db:
        for pattern in patterns:
            row = await db.scalar(
                select(AttackPattern)
                .where(
                    AttackPattern.source == args.source,
                    AttackPattern.category == pattern["category"],
                )
                .order_by(AttackPattern.id.asc())
                .limit(1)
            )
            if row is None:
                row = AttackPattern(
                    source=args.source,
                    category=pattern["category"],
                    subcategory=pattern["subcategory"],
                    severity=pattern["severity"],
                    prompt_text=pattern["prompt_text"],
                    language="mixed",
                )
                db.add(row)
                inserted += 1
            else:
                row.subcategory = pattern["subcategory"]
                row.severity = pattern["severity"]
                row.prompt_text = pattern["prompt_text"]
                row.language = "mixed"
                updated += 1
        await db.commit()

    print(f"[RuntimeAttackPattern] file={path} source={args.source} updated={updated} inserted={inserted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
