"""
Phase3~4 단독 실행용: 공격 패턴 JSON을 phase1/phase2 결과 형태로 변환한다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _patterns_from_payload(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("patterns"), list):
        return [x for x in data["patterns"] if isinstance(x, dict)]
    return []


def load_patterns_json(path: Path) -> list[dict[str, Any]]:
    """attack_patterns JSON (배열 또는 {patterns: [...]})을 로드한다."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = _patterns_from_payload(raw)
    if not out:
        raise ValueError(f"공격 패턴이 비어 있음: {path}")
    return out


def build_synthetic_phase_results(patterns: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    phase3가 기대하는 phase1/phase2 결과 dict를 만든다.
    각 패턴은 source_phase(또는 phase)로 1→vulnerable_attacks, 2→results에 분배된다.
    """
    p1_attacks: list[dict[str, Any]] = []
    p2_results: list[dict[str, Any]] = []

    for row in patterns:
        sp = row.get("source_phase")
        if sp is None:
            sp = row.get("phase")
        try:
            phase_num = int(sp) if sp is not None else 1
        except (TypeError, ValueError):
            phase_num = 1
        if phase_num not in (1, 2):
            phase_num = 1

        tid = str(row.get("test_result_id") or row.get("id") or "").strip()
        base: dict[str, Any] = {
            **row,
            "judgment": "vulnerable",
            "phase": phase_num,
            "attack_prompt": str(row.get("attack_prompt") or "").strip(),
            "target_response": str(row.get("target_response") or ""),
            "category": str(row.get("category") or ""),
            "subcategory": str(row.get("subcategory") or ""),
            "seed_id": str(row.get("seed_id") or ""),
            "severity": row.get("severity"),
            "detail": str(row.get("detail") or row.get("judge_reason") or ""),
        }
        if tid:
            base["test_result_id"] = tid

        if phase_num == 2:
            p2_results.append(base)
        else:
            p1_attacks.append(base)

    phase1_result: dict[str, Any] = {
        "total_scanned": len(p1_attacks),
        "vulnerable_count": len(p1_attacks),
        "safe_count": 0,
        "ambiguous_count": 0,
        "error_count": 0,
        "vulnerable_attacks": p1_attacks,
        "seed_mode": "phase34_only",
    }
    phase2_result: dict[str, Any] = {
        "results": p2_results,
        "seed_mode": "phase34_only",
    }
    return phase1_result, phase2_result


def load_phase34_seed(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """파일 경로에서 로드 후 synthetic phase1/phase2 결과를 반환한다."""
    patterns = load_patterns_json(path)
    return build_synthetic_phase_results(patterns)


def truncate_phase34_seed(
    phase1_result: dict[str, Any],
    phase2_result: dict[str, Any],
    max_cases: int | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    스모크에서 --max-attacks 로 시드 건수를 맞출 때 사용한다.
    Phase3와 동일하게 phase1 vulnerable_attacks 다음 phase2 results 순으로 자른다.
    """
    if max_cases is None or max_cases < 0:
        return phase1_result, phase2_result

    p1 = list(phase1_result.get("vulnerable_attacks") or [])
    p2 = list((phase2_result or {}).get("results") or [])
    take_p1 = min(len(p1), max_cases)
    new_p1 = p1[:take_p1]
    rest = max_cases - take_p1
    new_p2 = p2[:rest] if rest > 0 else []

    out1 = dict(phase1_result)
    out1["vulnerable_attacks"] = new_p1
    out1["total_scanned"] = len(new_p1)
    out1["vulnerable_count"] = len(new_p1)

    out2 = dict(phase2_result or {})
    out2["results"] = new_p2
    return out1, out2
