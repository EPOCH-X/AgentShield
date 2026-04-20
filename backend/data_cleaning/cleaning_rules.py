from __future__ import annotations

from collections import Counter
from typing import Iterable

from backend.core.judge import _has_meta_analysis, _has_refusal

VALID_TRAINING_JUDGMENTS = {"safe", "vulnerable", "ambiguous"}
VALID_DPO_JUDGMENTS = {"safe", "vulnerable"}
VALID_CATEGORIES = {"LLM01", "LLM02", "LLM06", "LLM07"}


def assess_training_record(record: dict, allowed_judgments: set[str] | None = None) -> list[str]:
    reasons: list[str] = []
    judgment = (record.get("judgment") or "").strip()
    category = (record.get("category") or "").strip()
    attack_prompt = (record.get("attack_prompt") or record.get("mutated_prompt") or "").strip()
    target_response = (record.get("target_response") or "").strip()

    if not attack_prompt:
        reasons.append("missing_attack_prompt")
    if not target_response:
        reasons.append("missing_target_response")
    if not judgment:
        reasons.append("missing_judgment")
    elif allowed_judgments is not None and judgment not in allowed_judgments:
        reasons.append(f"invalid_judgment:{judgment}")
    if not category:
        reasons.append("missing_category")
    elif category not in VALID_CATEGORIES:
        reasons.append(f"invalid_category:{category}")

    if judgment == "vulnerable" and target_response:
        if _has_refusal(target_response):
            reasons.append("vulnerable_with_refusal_response")
        if _has_meta_analysis(target_response):
            reasons.append("vulnerable_with_meta_analysis")

    return reasons


def split_clean_records(
    records: Iterable[dict],
    *,
    allowed_judgments: set[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    clean_records: list[dict] = []
    excluded_records: list[dict] = []

    for record in records:
        normalized = dict(record)
        reasons = assess_training_record(normalized, allowed_judgments=allowed_judgments)
        if reasons:
            normalized["exclusion_reasons"] = reasons
            excluded_records.append(normalized)
            continue
        clean_records.append(normalized)

    return clean_records, excluded_records


def summarize_exclusion_reasons(excluded_records: Iterable[dict]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for record in excluded_records:
        counter.update(record.get("exclusion_reasons") or [])
    return dict(sorted(counter.items()))