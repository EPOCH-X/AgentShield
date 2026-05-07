#!/usr/bin/env python3
"""
phase1to4 스모크 결과 JSON 하나에서 Blue SFT용 JSONL을 생성하고
카테고리/라벨별로 stratified train/val/test(80/10/10)로 나누어 저장한다.

입력:
  - --source: results/phase1to4_smoke_*.json (full state)

출력(default --out-dir=data/finetuning):
  - blue_train.jsonl
  - blue_val.jsonl
  - blue_test.jsonl

각 행 스키마:
  - instruction: "" (프롬프트는 input에 모두 포함)
  - input: build_blue_prompt(category, attack_prompt, target_response, judge_detail, ...)
  - output: JSON 문자열 {"defended_response": ..., "defense_rationale": ...}
  - category: LLM01~LLM07
  - label: "safe" (현재는 Phase4 최종 safe만 사용)
  - defense_id, meta_session_id, meta_source_smoke 등 메타 필드
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agents.blue_agent import build_blue_prompt


def _last_phase4_verdict_by_defense_id(final_state: dict) -> dict[str, str]:
    """
    defense_id별 최종 verdict(safe/unsafe)를 smoke full state에서 추출.
    scripts/merge_blue_train_jsonl_and_smoke.py와 동일 로직을 독립 복사.
    """
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
    """
    phase3_history에 기록된 defense_json_files를 읽어 defense_id -> payload 매핑을 만든다.
    payload는 blue 방어 코드/라쇼날, 원본 공격/응답 등을 포함한다.
    """
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


def _rows_from_smoke(smoke: dict, *, smoke_stem: str, session_id: str | None) -> list[dict]:
    """
    phase1to4 full state JSON에서 Blue SFT용 행 리스트를 생성한다.

    - Phase4 최종 verdict가 safe인 defense_id만 사용
    - build_blue_prompt로 input 문자열 구성
    - output은 defended_response/defense_rationale JSON 문자열
    """
    verdicts = _last_phase4_verdict_by_defense_id(smoke)
    payloads = _defense_payload_by_id(smoke)

    rows: list[dict] = []

    for did, v in verdicts.items():
        if v != "safe":
            # 현재는 방어에 성공한 케이스만 사용
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
            # 공격 프롬프트나 방어 응답이 비어 있으면 학습에 부적합
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

        row = {
            "instruction": "",
            "input": prompt,
            "output": out_obj,
            "category": cat,
            "label": "safe",
            "defense_id": did,
            "meta_session_id": session_id or None,
            "meta_source_smoke": smoke_stem + ".json",
            "meta_origin": f"phase1to4_smoke:{smoke_stem}",
        }
        rows.append(row)

    return rows


def _stratified_split(
    rows: list[dict],
    *,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    category + label 기준으로 strata를 나누고 각 strata에서 train/val/test를 샘플링한다.

    - strata key: (category, label)
    - 각 strata 크기가 너무 작으면(예: < 5) 전부 train으로 보낸다.
    """
    rng = random.Random(seed)
    strata: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for row in rows:
        cat = str(row.get("category") or "").strip() or "UNSPEC"
        label = str(row.get("label") or "").strip() or "UNSPEC"
        strata[(cat, label)].append(row)

    train: list[dict] = []
    val: list[dict] = []
    test: list[dict] = []

    for (cat, label), bucket in strata.items():
        rng.shuffle(bucket)
        n = len(bucket)
        if n < 5:
            # 너무 작은 strata는 통째로 train에만 사용
            train.extend(bucket)
            continue

        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        n_test = n - n_train - n_val

        # 경계값 보정: 최소 1개씩 들어가도록 시도
        if n_val == 0 and n >= 6:
            n_val = 1
            n_train = max(n_train - 1, 0)
        if n_test == 0 and n >= 6:
            n_test = 1
            if n_train > n_val:
                n_train = max(n_train - 1, 0)
            else:
                n_val = max(n_val - 1, 0)

        train.extend(bucket[:n_train])
        val.extend(bucket[n_train : n_train + n_val])
        test.extend(bucket[n_train + n_val :])

    return train, val, test


def main() -> int:
    ap = argparse.ArgumentParser(description="Export Blue SFT JSONL from phase1to4 smoke full state JSON.")
    ap.add_argument(
        "--source",
        type=Path,
        required=True,
        help="phase1to4_smoke_*.json full state 경로",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/finetuning"),
        help="출력 디렉터리 (기본: data/finetuning)",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=42,
        help="stratified split 셔플 시드 (기본: 42)",
    )
    args = ap.parse_args()

    smoke_path: Path = args.source
    if not smoke_path.is_file():
        raise SystemExit(f"source JSON not found: {smoke_path}")

    smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    session_id = str(smoke.get("session_id") or "").strip() or None
    smoke_stem = smoke_path.stem

    rows = _rows_from_smoke(smoke, smoke_stem=smoke_stem, session_id=session_id)
    if not rows:
        raise SystemExit("no usable Blue SFT rows extracted from source JSON.")

    train_rows, val_rows, test_rows = _stratified_split(rows, seed=args.seed)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    train_path = out_dir / "blue_train.jsonl"
    val_path = out_dir / "blue_val.jsonl"
    test_path = out_dir / "blue_test.jsonl"

    def _dump_jsonl(path: Path, data: list[dict]) -> None:
        path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in data) + "\n",
            encoding="utf-8",
        )

    _dump_jsonl(train_path, train_rows)
    _dump_jsonl(val_path, val_rows)
    _dump_jsonl(test_path, test_rows)

    def _count_by(key: str, rows_list: list[dict]) -> dict[str, int]:
        cnt: dict[str, int] = defaultdict(int)
        for r in rows_list:
            k = str(r.get(key) or "").strip() or "UNSPEC"
            cnt[k] += 1
        return dict(sorted(cnt.items()))

    print(f"[export] source={smoke_path.name}")
    print(f"[export] total rows: {len(rows)}")
    print(
        f"[export] train/val/test sizes: "
        f"{len(train_rows)}/{len(val_rows)}/{len(test_rows)}"
    )
    print(f"[export] train by category: {_count_by('category', train_rows)}")
    print(f"[export] val by category:   {_count_by('category', val_rows)}")
    print(f"[export] test by category:  {_count_by('category', test_rows)}")
    print(f"[export] train by label:    {_count_by('label', train_rows)}")
    print(f"[export] val by label:      {_count_by('label', val_rows)}")
    print(f"[export] test by label:     {_count_by('label', test_rows)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

