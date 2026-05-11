from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


def append_jsonl(path: str | Path, item: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def write_jsonl(path: str | Path, items: Iterable[dict[str, Any]]) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with p.open("w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            count += 1
    return count


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def flatten_campaign_raw(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in data.get("items", []):
        base = {
            "campaign_id": data.get("campaign_id") or item.get("campaign_id", ""),
            "seed_id": item.get("seed_id") or item.get("id") or "",
            "category": item.get("category", ""),
            "subcategory": item.get("subcategory", ""),
        }
        for round_item in item.get("rounds", []):
            row = dict(base)
            row.update(round_item)
            row.setdefault("attack_prompt", round_item.get("mutated_prompt") or round_item.get("attack_prompt") or "")
            row.setdefault("target_response", round_item.get("target_response") or "")
            rows.append(row)
    return rows


def build_preference_pairs(
    rows: list[dict[str, Any]],
    *,
    chosen_min: float,
    rejected_max: float,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row.get("seed_id", "")), str(row.get("category", "")), int(row.get("round") or 0))].append(row)

    pairs: list[dict[str, Any]] = []
    for (_, _, _), group in grouped.items():
        chosen = [r for r in group if float(r.get("reward_score", 0.0)) >= chosen_min]
        rejected = [r for r in group if float(r.get("reward_score", 0.0)) <= rejected_max]
        if not chosen or not rejected:
            continue
        best = max(chosen, key=lambda r: float(r.get("reward_score", 0.0)))
        worst = min(rejected, key=lambda r: float(r.get("reward_score", 0.0)))
        pairs.append(
            {
                "prompt": best.get("red_prompt") or best.get("round_input_prompt") or best.get("original_attack_prompt") or "",
                "chosen": best.get("attack_prompt") or best.get("mutated_prompt") or "",
                "rejected": worst.get("attack_prompt") or worst.get("mutated_prompt") or "",
                "metadata": {
                    "seed_id": best.get("seed_id", ""),
                    "category": best.get("category", ""),
                    "round": best.get("round", 0),
                    "chosen_reward": best.get("reward_score"),
                    "rejected_reward": worst.get("reward_score"),
                    "chosen_reasons": best.get("reward_positives", []),
                    "rejected_reasons": worst.get("reward_negatives", []),
                },
            }
        )
    return pairs

