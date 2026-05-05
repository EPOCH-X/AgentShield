#!/usr/bin/env python3
"""
prep-plus-p1p4max30 (110행, meta 없음) + phase3~4 스모크 full state JSON 에서
Phase4 최종 verdict 가 safe 인 방어만 SFT 행으로 추출해 jsonl + meta 를 만든다.

prep-plus 행에는 원본에 없던 meta 를 합성해 줄 수를 맞춘다.

예:
  python scripts/merge_prep_plus_and_phase34_smoke.py \\
    --prep-plus-jsonl data/finetuning/blue_train_qwen35-2b-prep-plus-p1p4max30_20260504.jsonl \\
    --smoke-json results/phase3to4_smoke_20260504_181959_qwen3.5-4b_high_value_success_44.json \\
    --output-stem data/finetuning/blue_train_qwen35-2b-prep-plus-p1p4max30_20260504_plus_highvalue44_20260504_181959_v2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agents.blue_agent import build_blue_prompt


def _last_phase4_verdict_by_defense_id(final_state: dict) -> dict[str, str]:
    last: dict[str, str] = {}
    for entry in final_state.get("phase4_history") or []:
        if not isinstance(entry, dict):
            continue
        for d in entry.get("details") or []:
            if not isinstance(d, dict):
                continue
            did = str(d.get("defense_id") or "").strip()
            v = str(d.get("verdict") or "").strip()
            if did and v:
                last[did] = v
    if not last:
        p4 = final_state.get("phase4_result") or {}
        for d in p4.get("details") or []:
            if not isinstance(d, dict):
                continue
            did = str(d.get("defense_id") or "").strip()
            v = str(d.get("verdict") or "").strip()
            if did and v:
                last[did] = v
    return last


def _defense_payload_by_id(final_state: dict) -> dict[str, dict]:
    """phase3_history 의 defense_json_files 순서대로 읽어 defense_id -> 최종 payload."""
    out: dict[str, dict] = {}
    for entry in final_state.get("phase3_history") or []:
        if not isinstance(entry, dict):
            continue
        for rel in entry.get("defense_json_files") or []:
            path = PROJECT_ROOT / str(rel)
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            did = str(payload.get("defense_id") or "").strip()
            if did:
                out[did] = payload
    return out


def _rows_from_smoke(smoke: dict, *, smoke_stem: str, session_id: str) -> tuple[list[dict], list[dict]]:
    verdicts = _last_phase4_verdict_by_defense_id(smoke)
    payloads = _defense_payload_by_id(smoke)
    rows_j: list[dict] = []
    rows_m: list[dict] = []

    for did, v in verdicts.items():
        if v != "safe":
            continue
        payload = payloads.get(did)
        if not payload:
            continue
        cat = str(payload.get("category") or "").strip()
        attack = str(payload.get("attack_prompt") or "").strip()
        target_resp = str(payload.get("target_response") or "")
        judge_detail = str(payload.get("judge_reason") or "").strip()
        dr = str(payload.get("defended_response") or "").strip()
        dra = str(payload.get("defense_rationale") or "").strip()
        if not attack or not dr:
            continue

        prompt = build_blue_prompt(
            cat,
            attack,
            target_response=target_resp,
            judge_detail=judge_detail,
            failure_mode=None,
            mitre_technique_id=None,
        )
        out_obj = json.dumps(
            {"defended_response": dr, "defense_rationale": dra},
            ensure_ascii=False,
        )
        rows_j.append({"instruction": "", "input": prompt, "output": out_obj})
        rows_m.append(
            {
                "instruction": "",
                "input": prompt,
                "output": out_obj,
                "meta_session_id": session_id or None,
                "meta_defense_id": did,
                "meta_source_smoke": smoke_stem + ".json",
                "meta_merge_row_origin": f"phase34_smoke:{smoke_stem}",
            }
        )
    return rows_j, rows_m


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prep-plus-jsonl", type=Path, required=True)
    ap.add_argument("--smoke-json", type=Path, required=True)
    ap.add_argument(
        "--output-stem",
        type=Path,
        required=True,
        help="확장자 없이 전체 경로 stem (예 data/finetuning/foo_v2)",
    )
    args = ap.parse_args()

    prep_path: Path = args.prep_plus_jsonl
    smoke_path: Path = args.smoke_json
    out_stem: Path = args.output_stem

    base_rows = [
        json.loads(l)
        for l in prep_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    stem_pp = prep_path.stem
    base_meta: list[dict] = []
    for i, r in enumerate(base_rows, start=1):
        m = {
            "instruction": r.get("instruction", ""),
            "input": r.get("input", ""),
            "output": r.get("output", ""),
            "meta_session_id": None,
            "meta_defense_id": f"{stem_pp}-line-{i}",
            "meta_source_smoke": prep_path.name,
            "meta_merge_row_origin": f"base:{stem_pp}",
        }
        base_meta.append(m)

    smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    session_id = str(smoke.get("session_id") or "").strip()
    smoke_stem = smoke_path.stem
    add_j, add_m = _rows_from_smoke(
        smoke, smoke_stem=smoke_stem, session_id=session_id
    )

    out_j = base_rows + add_j
    out_m = base_meta + add_m

    out_jsonl = Path(str(out_stem) + ".jsonl")
    out_meta = Path(str(out_stem) + ".meta.jsonl")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    out_jsonl.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in out_j) + "\n",
        encoding="utf-8",
    )
    out_meta.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in out_m) + "\n",
        encoding="utf-8",
    )

    print(
        f"[merge] base={prep_path.name} ({len(base_rows)}) "
        f"+ phase34_safe={len(add_j)} -> {out_jsonl} ({len(out_j)} rows)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
