#!/usr/bin/env python3
"""Rejected SFT 샘플 통계 분석.

여러 rejected.json 파일을 읽어서 거부 사유별 분포, 길이, 언어, encoding directive
분포를 출력한다. 이 통계를 보고 어떤 사유를 bulk-keep / bulk-discard / LLM judge로
보낼지 결정한다.

GPU/LLM 사용 안 함 — 빌드 스크립트 돌고 있어도 안전.

사용법:
  venv/bin/python scripts/analyze_rejected.py \
    /tmp/agentshield-finetuning/red_v4.rejected.json \
    /tmp/agentshield-finetuning/red_v5.rejected.json \
    /tmp/agentshield-finetuning/red_v8.1.rejected.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# 언어별 유니코드 블록
LANG_RANGES: list[tuple[str, re.Pattern[str]]] = [
    ("ko", re.compile(r"[가-힣]")),
    ("zh", re.compile(r"[一-鿿]")),
    ("ja", re.compile(r"[぀-ヿ]")),
    ("ar", re.compile(r"[؀-ۿ]")),
    ("cyr", re.compile(r"[Ѐ-ӿ]")),
]

ENCODING_LABELS: dict[int, str] = {
    0: "ko-frame",
    1: "zh-frame",
    2: "base64",
    3: "hex/binary",
    4: "unicode-homo",
    5: "split-payload",
    6: "ja-frame",
    7: "ar-frame",
    8: "ko-en-mix",
    9: "rot13/caesar",
    10: "homo+b64",
    11: "std-en",
}


def detect_language(text: str) -> str:
    if not text:
        return "?"
    counts: dict[str, int] = {label: len(rx.findall(text)) for label, rx in LANG_RANGES}
    counts["en"] = sum(1 for c in text if 0x20 <= ord(c) <= 0x7E)
    total = sum(counts.values())
    if total == 0:
        return "?"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(len(s) * q)))
    return s[idx]


def fmt_dist(c: Counter, top: int = 6) -> str:
    return "  ".join(f"{k}={v}" for k, v in c.most_common(top))


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze rejected SFT samples.")
    ap.add_argument("files", nargs="+", help="rejected.json 파일 (여러 개 가능)")
    ap.add_argument("--head-chars", type=int, default=180, help="샘플 미리보기 길이")
    ap.add_argument("--samples-per-reason", type=int, default=2)
    args = ap.parse_args()

    all_samples: list[dict[str, Any]] = []
    per_file: list[tuple[str, int]] = []
    for f in args.files:
        path = Path(f)
        if not path.exists():
            print(f"[WARN] not found: {f}", file=sys.stderr)
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for s in data:
            s["_source_file"] = path.name
        all_samples.extend(data)
        per_file.append((path.name, len(data)))

    if not all_samples:
        print("[ERROR] no samples loaded", file=sys.stderr)
        return 2

    print("=" * 80)
    print("FILES")
    print("=" * 80)
    for name, n in per_file:
        print(f"  {n:5d}  {name}")
    print(f"  {sum(n for _, n in per_file):5d}  TOTAL")
    print()

    by_reason: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in all_samples:
        by_reason[s.get("rejection_reason", "?")].append(s)

    print("=" * 80)
    print("REJECTION REASONS (sorted by count)")
    print("=" * 80)
    for reason, items in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
        n = len(items)
        pct = 100 * n / len(all_samples)
        print(f"\n[{n:4d}  {pct:5.1f}%]  {reason}")
        print("-" * 80)

        # 길이 분포
        norm_lens = [int(s.get("normalized_output_len") or 0) for s in items]
        raw_lens = [int(s.get("raw_output_len") or 0) for s in items]
        print(
            f"  length    : raw  p50={percentile(raw_lens, 0.5):>6}  p90={percentile(raw_lens, 0.9):>6}"
            f"  |  norm p50={percentile(norm_lens, 0.5):>6}  p90={percentile(norm_lens, 0.9):>6}"
        )

        # 언어 (raw 기준 — 모델 원본 출력)
        langs = Counter(detect_language(s.get("raw_output", "") or "") for s in items)
        print(f"  language  : {fmt_dist(langs)}")

        # encoding directive
        encs = Counter(ENCODING_LABELS.get(int(s.get("encoding_index") or -1), "?") for s in items)
        print(f"  encoding  : {fmt_dist(encs)}")

        # category / domain
        cats = Counter(s.get("category", "?") for s in items)
        doms = Counter(s.get("domain", "?") for s in items)
        print(f"  category  : {fmt_dist(cats)}")
        print(f"  domain    : {fmt_dist(doms)}")

        # 샘플 헤드 (다른 인코딩 인덱스끼리 다양하게)
        seen_encs: set[int] = set()
        shown = 0
        for s in items:
            ei = int(s.get("encoding_index") or -1)
            if ei in seen_encs and shown >= 1:
                continue
            seen_encs.add(ei)
            head = (s.get("raw_output", "") or "").replace("\n", " / ")[: args.head_chars]
            print(
                f"  ex{shown + 1} [{s.get('_source_file')} seed={s.get('seed_index')} "
                f"enc={ENCODING_LABELS.get(ei, '?')}]: {head}"
            )
            shown += 1
            if shown >= args.samples_per_reason:
                break

    return 0


if __name__ == "__main__":
    sys.exit(main())
