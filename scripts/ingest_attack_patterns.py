#!/usr/bin/env python3
"""Ingest curated JSON attack prompts into attack_patterns.

Examples:
  DATABASE_URL='postgresql+asyncpg://user:pass@host:5432/agentshield?ssl=require' \
    python scripts/ingest_attack_patterns.py \
      --path data/curated_attack_sets/testbed_manual_mixed_10.json \
      --source manual_reviewed_830_testbed10 \
      --replace-source
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.engine import make_url


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings  # noqa: E402
from backend.database import async_session  # noqa: E402
from backend.models.attack_pattern import AttackPattern  # noqa: E402


PROMPT_KEYS = (
    "attack_prompt",
    "prompt_text",
    "mutated_prompt",
    "original_prompt",
    "text",
)


@dataclass(frozen=True)
class NormalizedPattern:
    prompt_text: str
    category: str
    subcategory: str | None
    severity: str
    source: str
    language: str


def _masked_url(raw_url: str) -> str:
    return make_url(raw_url).render_as_string(hide_password=True)


def _load_json(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        raw_items = data.get("patterns") or data.get("items") or [data]
    else:
        raise ValueError(f"Unsupported JSON root type: {type(data).__name__}")
    return [item for item in raw_items if isinstance(item, dict)]


def _first_text(item: dict[str, Any]) -> str:
    for key in PROMPT_KEYS:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _normalize_severity(value: Any) -> str:
    severity = str(value or "medium").strip().lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    return "medium"


def _normalize_item(
    item: dict[str, Any],
    *,
    source: str,
    only_judgment: str,
    language: str,
) -> NormalizedPattern | None:
    metadata = _metadata(item)
    judgment = str(item.get("judgment") or metadata.get("judgment") or "").strip().lower()
    if only_judgment != "all" and judgment != only_judgment:
        return None

    prompt_text = _first_text(item)
    if not prompt_text:
        return None

    category = str(item.get("category") or metadata.get("category") or "").strip()
    if not category:
        return None

    subcategory = str(item.get("subcategory") or metadata.get("subcategory") or "").strip() or None
    severity = _normalize_severity(item.get("severity") or metadata.get("severity"))

    return NormalizedPattern(
        prompt_text=prompt_text,
        category=category,
        subcategory=subcategory,
        severity=severity,
        source=source,
        language=language,
    )


async def _source_count(source: str) -> int:
    async with async_session() as db:
        result = await db.execute(
            select(func.count()).select_from(AttackPattern).where(AttackPattern.source == source)
        )
        return int(result.scalar_one())


async def _total_count() -> int:
    async with async_session() as db:
        result = await db.execute(select(func.count()).select_from(AttackPattern))
        return int(result.scalar_one())


async def ingest(
    patterns: list[NormalizedPattern],
    *,
    source: str,
    replace_source: bool,
    dry_run: bool,
) -> tuple[int, int]:
    if dry_run:
        return (0, 0)

    inserted = 0
    skipped = 0
    async with async_session() as db:
        if replace_source:
            await db.execute(delete(AttackPattern).where(AttackPattern.source == source))

        existing_rows = await db.execute(
            select(AttackPattern.prompt_text).where(AttackPattern.source == source)
        )
        existing_prompts = set(existing_rows.scalars().all())

        for pattern in patterns:
            if pattern.prompt_text in existing_prompts:
                skipped += 1
                continue
            db.add(
                AttackPattern(
                    prompt_text=pattern.prompt_text,
                    category=pattern.category,
                    subcategory=pattern.subcategory,
                    severity=pattern.severity,
                    source=pattern.source,
                    language=pattern.language,
                )
            )
            existing_prompts.add(pattern.prompt_text)
            inserted += 1

        await db.commit()
    return inserted, skipped


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True, help="Curated JSON file path.")
    parser.add_argument("--source", required=True, help="Source label stored in attack_patterns.source.")
    parser.add_argument(
        "--only-judgment",
        choices=("all", "vulnerable", "safe", "ambiguous"),
        default="all",
        help="Filter by manual judgment before ingest.",
    )
    parser.add_argument("--language", default="mixed", help="Stored language label.")
    parser.add_argument("--replace-source", action="store_true", help="Delete rows with the same source before ingest.")
    parser.add_argument("--dry-run", action="store_true", help="Parse and count only.")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        print(f"[AttackPattern] file not found: {path}", flush=True)
        return 2

    raw_items = _load_json(path)
    patterns = [
        pattern
        for item in raw_items
        if (
            pattern := _normalize_item(
                item,
                source=args.source,
                only_judgment=args.only_judgment,
                language=args.language,
            )
        )
    ]

    print(f"[AttackPattern] db={_masked_url(settings.DATABASE_URL)}", flush=True)
    print(
        f"[AttackPattern] file={path} raw={len(raw_items)} normalized={len(patterns)} "
        f"judgment={args.only_judgment} source={args.source}",
        flush=True,
    )
    inserted, skipped = await ingest(
        patterns,
        source=args.source,
        replace_source=args.replace_source,
        dry_run=args.dry_run,
    )
    source_total = 0 if args.dry_run else await _source_count(args.source)
    all_total = 0 if args.dry_run else await _total_count()
    print(
        f"[AttackPattern] inserted={inserted} skipped={skipped} "
        f"source_total={source_total} all_total={all_total}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
