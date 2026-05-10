#!/usr/bin/env python3
"""거부 사유 분석 결과를 바탕으로 rejected 샘플을 일괄 처리한다.

분석(analyze_rejected.py)으로 도출된 결정 규칙:

  KEEP (raw_output 사용):
    - "generic stale carrier" 사유 → mutation_engine 부작용. raw는 깨끗
    - "hardcoded sample identifier ..." + encoding_index ∈ BASE64_DIRECTIVE_INDICES
      → directive가 base64 출력 요구한 케이스. validator의 base64 regex가 오인

  DISCARD:
    - "too long: ..." 모든 케이스 → <think> 모드 폭주 출력
    - "too short: 0" → normalize 후 빈 문자열 (전체가 <think> 블록이었음)

  JUDGE_PENDING (이후 LLM judge 단계로):
    - "hardcoded sample identifier ..." + encoding_index NOT in BASE64_DIRECTIVE_INDICES
    - "instruction scaffold leaked"

  MANUAL_PENDING (사람이 직접 봐야):
    - 그 외 모든 사유 (chat role label, supplied secret, example row, too short non-zero 등)

GPU/LLM 호출 없음.

사용법:
venv/bin/python scripts/bulk_process_rejected.py \
    data/finetuning/red_v4.rejected.json \
    data/finetuning/red_v5.rejected.json \
    data/finetuning/red_v6.rejected.json \
    data/finetuning/red_v7.rejected.json \
    data/finetuning/red_v8.rejected.json \
    data/finetuning/red_v8.1.rejected.json \
    --output-dir data/finetuning/bulk
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agents.red_sft_seed_agent import (  # noqa: E402
    compact_sft_training_user,
    get_sft_seed_system_prompt,
)

# ★ NOTE: 현재 rejected 파일들(v4~v8.1)은 hex/binary directive 제거 전 OLD numbering(0~11)으로
#   생성됐다. OLD에서 base64 directive는 인덱스 2(base64), 10(homo+b64).
#   v9+ 부터 새 numbering(0~10)을 쓰면 base64 directive는 인덱스 2, 9 가 된다.
#   OLD 파일만 처리하므로 OLD 값을 사용한다.
BASE64_DIRECTIVE_INDICES_OLD = {2, 10}


def _classify(sample: dict[str, Any]) -> str:
    reason = (sample.get("rejection_reason") or "").lower()
    enc_idx = sample.get("encoding_index")
    norm_len = int(sample.get("normalized_output_len") or 0)

    if "generic stale carrier" in reason:
        return "keep"

    if "hardcoded sample identifier" in reason:
        if isinstance(enc_idx, int) and enc_idx in BASE64_DIRECTIVE_INDICES_OLD:
            return "keep"
        return "judge"

    if reason.startswith("too long"):
        return "discard"

    if reason.startswith("too short"):
        # too short: 0 → 전부 <think>이라 빈 norm. 폐기. 그 외는 manual.
        if norm_len == 0:
            return "discard"
        return "manual"

    if "instruction scaffold leaked" in reason:
        return "judge"

    return "manual"


def _to_message(sample: dict[str, Any], system_prompt: str) -> dict[str, Any]:
    """KEEP 결정에는 항상 raw_output 사용 (mutation_engine prefix 없는 깨끗한 모델 출력)."""
    content = sample.get("raw_output", "") or ""
    user_prompt = compact_sft_training_user(
        category=sample.get("category") or "LLM01",
        subcategory=sample.get("subcategory") or "",
        domain=sample.get("domain") or "general",
    )
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": content},
        ]
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Bulk-process rejected SFT samples by decision rules.")
    ap.add_argument("files", nargs="+", help="rejected.json 파일")
    ap.add_argument("--output-dir", default="data/finetuning/bulk", help="결과 폴더")
    ap.add_argument("--prefix", default="bulk", help="출력 파일 prefix")
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rescued_path = out_dir / f"{args.prefix}_rescued.jsonl"
    judge_path = out_dir / f"{args.prefix}_judge_pending.json"
    manual_path = out_dir / f"{args.prefix}_manual_pending.json"
    discarded_path = out_dir / f"{args.prefix}_discarded.json"
    summary_path = out_dir / f"{args.prefix}_summary.json"

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

    rescued: list[dict[str, Any]] = []
    judge_pending: list[dict[str, Any]] = []
    manual_pending: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []
    decision_counts: Counter[str] = Counter()
    by_reason_action: Counter[tuple[str, str]] = Counter()

    system_prompt = get_sft_seed_system_prompt()

    for s in all_samples:
        decision = _classify(s)
        decision_counts[decision] += 1
        reason = s.get("rejection_reason", "?")
        by_reason_action[(reason, decision)] += 1

        if decision == "keep":
            rescued.append(_to_message(s, system_prompt))
        elif decision == "judge":
            judge_pending.append(s)
        elif decision == "manual":
            manual_pending.append(s)
        else:  # discard
            discarded.append({
                "source_file": s.get("_source_file"),
                "seed_index": s.get("seed_index"),
                "attempt": s.get("attempt"),
                "rejection_reason": reason,
                "raw_output_len": s.get("raw_output_len"),
            })

    with rescued_path.open("w", encoding="utf-8") as f:
        for msg in rescued:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")
    judge_path.write_text(json.dumps(judge_pending, ensure_ascii=False, indent=2), encoding="utf-8")
    manual_path.write_text(json.dumps(manual_pending, ensure_ascii=False, indent=2), encoding="utf-8")
    discarded_path.write_text(json.dumps(discarded, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        "input_files": [{"name": n, "count": c} for n, c in per_file],
        "total_samples": len(all_samples),
        "decisions": dict(decision_counts),
        "by_reason_action": [
            {"reason": r, "action": a, "count": c}
            for (r, a), c in sorted(by_reason_action.items(), key=lambda kv: -kv[1])
        ],
        "outputs": {
            "rescued_jsonl": str(rescued_path),
            "judge_pending": str(judge_path),
            "manual_pending": str(manual_path),
            "discarded": str(discarded_path),
        },
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"input:        {len(all_samples)} samples from {len(per_file)} files")
    print(f"decisions:    {dict(decision_counts)}")
    print()
    print(f"rescued ({len(rescued)})         → {rescued_path}")
    print(f"judge ({len(judge_pending)})           → {judge_path}")
    print(f"manual ({len(manual_pending)})          → {manual_path}")
    print(f"discarded ({len(discarded)})       → {discarded_path}")
    print(f"summary               → {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
