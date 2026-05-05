#!/usr/bin/env python3
"""
기존 Blue 학습 jsonl(+meta) 뒤에 phase3~4 또는 phase1to4 스모크 full state JSON 에서
Phase4 최종 safe 방어 SFT 행을 붙인다. base 와 동일한 input 해시는 건너뛴다.

예:
  python scripts/merge_blue_train_jsonl_and_smoke.py \\
    --base-jsonl data/finetuning/blue_train_qwen35-2b-prep-plus-p1p4max30_20260504_plus_highvalue44_20260504_181959_v2.jsonl \\
    --base-meta data/finetuning/blue_train_qwen35-2b-prep-plus-p1p4max30_20260504_plus_highvalue44_20260504_181959_v2.meta.jsonl \\
    --smoke-json results/phase1to4_smoke_20260505_040443_qwen3.5-4b_cat-all-maxall.json \\
    --output-stem data/finetuning/blue_train_qwen35-2b-prep-plus-p1p4max30_20260504_plus_highvalue44_20260504_181959_plus_phase1to4_20260505_040443_v3
"""

from __future__ import annotations

import argparse
import hashlib
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


def _inp_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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
                "meta_merge_row_origin": f"phase_smoke:{smoke_stem}",
            }
        )
    return rows_j, rows_m


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-jsonl", type=Path, required=True)
    ap.add_argument("--base-meta", type=Path, required=True)
    ap.add_argument("--smoke-json", type=Path, required=True)
    ap.add_argument("--output-stem", type=Path, required=True)
    args = ap.parse_args()

    base_j = [
        json.loads(l)
        for l in args.base_jsonl.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    base_m = [
        json.loads(l)
        for l in args.base_meta.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    if len(base_j) != len(base_m):
        raise SystemExit(f"base 줄 수 불일치: jsonl={len(base_j)} meta={len(base_m)}")

    seen = {_inp_hash(r["input"]) for r in base_j}
    smoke = json.loads(args.smoke_json.read_text(encoding="utf-8"))
    session_id = str(smoke.get("session_id") or "").strip()
    smoke_stem = args.smoke_json.stem
    add_j, add_m = _rows_from_smoke(smoke, smoke_stem=smoke_stem, session_id=session_id)

    out_j = list(base_j)
    out_m = list(base_m)
    skipped_dup = 0
    for rj, rm in zip(add_j, add_m, strict=True):
        h = _inp_hash(rj["input"])
        if h in seen:
            skipped_dup += 1
            continue
        seen.add(h)
        out_j.append(rj)
        out_m.append(rm)

    out_stem = args.output_stem
    out_stem.parent.mkdir(parents=True, exist_ok=True)
    out_jsonl = Path(str(out_stem) + ".jsonl")
    out_meta = Path(str(out_stem) + ".meta.jsonl")
    out_jsonl.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in out_j) + "\n",
        encoding="utf-8",
    )
    out_meta.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in out_m) + "\n",
        encoding="utf-8",
    )

    print(
        f"[merge] base={args.base_jsonl.name} ({len(base_j)}) "
        f"+ smoke_safe={len(add_j)} (deduped_add={len(out_j) - len(base_j)}, skipped_dup={skipped_dup}) "
        f"-> {out_jsonl.name} total={len(out_j)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
