#!/usr/bin/env python3
"""
Split attack-pattern JSON array into train/val/test with simple stratification.

Default: stratify by (category, judgment|verdict), seed=42, ratios 0.8/0.1/0.1.

Example:
  python scripts/split_attack_dataset.py \
    --in data/attack_patterns/merged_temp_high44_plus_review830.json \
    --out-dir data/attack_patterns/splits \
    --prefix merged_high44_review830 \
    --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _label(row: dict[str, Any]) -> tuple[str, str]:
    cat = str(row.get("category") or "UNKNOWN").strip() or "UNKNOWN"
    j = (row.get("judgment") or row.get("verdict") or "UNKNOWN")
    j = str(j).strip().lower() or "unknown"
    return cat, j


def _safe_ratio_to_counts(n: int, *, r_train: float, r_val: float, r_test: float) -> tuple[int, int, int]:
    if n <= 0:
        return 0, 0, 0
    # Round then fix sum; keep at least 1 train if possible.
    n_val = int(round(n * r_val))
    n_test = int(round(n * r_test))
    n_train = n - n_val - n_test
    if n_train <= 0:
        n_train = 1
        rem = n - n_train
        n_val = rem // 2
        n_test = rem - n_val
    if n_train + n_val + n_test != n:
        n_train = n - n_val - n_test
    return n_train, n_val, n_test


def main() -> int:
    ap = argparse.ArgumentParser(description="Split attack dataset JSON into train/val/test")
    ap.add_argument("--in", dest="in_path", required=True, help="input JSON file (array)")
    ap.add_argument("--out-dir", required=True, help="output directory")
    ap.add_argument("--prefix", default="split", help="output file prefix")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train", type=float, default=0.8)
    ap.add_argument("--val", type=float, default=0.1)
    ap.add_argument("--test", type=float, default=0.1)
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("input must be a JSON array")
    data: list[dict[str, Any]] = [x for x in raw if isinstance(x, dict)]

    rnd = random.Random(args.seed)

    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in data:
        buckets[_label(row)].append(row)

    train: list[dict[str, Any]] = []
    val: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []

    for key, rows in buckets.items():
        rows = list(rows)
        rnd.shuffle(rows)
        n = len(rows)
        n_train, n_val, n_test = _safe_ratio_to_counts(n, r_train=args.train, r_val=args.val, r_test=args.test)
        train.extend(rows[:n_train])
        val.extend(rows[n_train : n_train + n_val])
        test.extend(rows[n_train + n_val : n_train + n_val + n_test])

    # Final shuffle within each split (stable seed)
    rnd.shuffle(train)
    rnd.shuffle(val)
    rnd.shuffle(test)

    def dump(name: str, rows: list[dict[str, Any]]) -> Path:
        p = out_dir / f"{args.prefix}_{name}.json"
        p.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return p

    p_train = dump("train", train)
    p_val = dump("val", val)
    p_test = dump("test", test)

    def counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
        c = Counter(f"{a}/{b}" for (a, b) in (_label(r) for r in rows))
        top = dict(c.most_common(10))
        j = Counter((_label(r)[1] for r in rows))
        return {"n": len(rows), "judgment": dict(j), "top10_cat_judgment": top}

    print("[split] input:", in_path)
    print("[split] output:", out_dir)
    print("[split] train:", p_train)
    print("[split] val  :", p_val)
    print("[split] test :", p_test)
    print("[split] train_counts:", counts(train))
    print("[split] val_counts  :", counts(val))
    print("[split] test_counts :", counts(test))
    print("[split] total:", len(train) + len(val) + len(test))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

