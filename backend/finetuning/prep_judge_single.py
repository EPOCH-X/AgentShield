"""
AgentShield Consensus-only SFT 데이터셋 전처리 파이프라인

목적:
- benchmark_result.json에서 consensus 학습용 데이터만 추출
- base / strict_safe_advocate / context_vulnerable_advocate row는 생성하지 않음
- 실제 judge_agent 런타임의 build_consensus_judge_messages를 그대로 사용
- QLoRA 학습용 messages JSONL 포맷 생성

핵심 조건:
1. expected_judgment가 vulnerable/safe인 샘플만 사용
2. expected != predicted 샘플도 버리지 않음
3. assistant 정답 judgment는 항상 expected_judgment 사용
4. reason은 expected_judgment와 논리적으로 정렬된 reason만 사용
   우선순위:
   - benchmark_flattened에서 같은 sample_id/category/response_type의 judgment == expected인 reason
   - consensus.judgment == expected 이고 consensus.reason 유효하면 사용
   - sample.detail 유효하면 사용
   - expected == safe 이고 strict.reason 유효하면 사용
   - expected == vulnerable 이고 context.reason 유효하면 사용
   - 없으면 skip
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =========================
# PATH
# =========================

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================
# IMPORT
# =========================

try:
    from backend.agents.judge_agent import build_consensus_judge_messages
except ImportError as e:
    print(f"[오류] judge_agent import 실패: {e}")
    sys.exit(1)


# =========================
# FILE PATH
# =========================

INPUT_DATA_PATH = PROJECT_ROOT / "data" / "benchmark_result.json"
FLATTENED_DATA_PATH = PROJECT_ROOT / "data" / "benchmark_flattened.json"
OUTPUT_DATA_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train_consensus_only.jsonl"

VALID_LABELS = {"vulnerable", "safe"}


# =========================
# HELPERS
# =========================

def clean_text(text: Any, max_len: int = 1000) -> str:
    text = "" if text is None else str(text)
    text = " ".join(text.replace("\n", " ").replace("\r", " ").split())

    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def safe_truncate(text: Any, max_chars: int = 1600) -> str:
    text = "" if text is None else str(text)
    if len(text) > max_chars:
        return text[: max_chars - 3] + "..."
    return text


def normalize_label(value: Any) -> str:
    return str(value or "").strip().lower()


def is_valid_reason(reason: Any) -> bool:
    reason = clean_text(reason)

    if not reason:
        return False

    bad_reasons = {
        "Parsed JSON response without reason.",
        "Strict auditor returned invalid JSON after repair attempt.",
        "Context auditor returned invalid JSON after repair attempt.",
        "Strict auditor invalid json.",
        "Context auditor invalid json.",
        "Consensus auditor invalid json.",
        "Consensus returned invalid JSON after repair attempt.",
        "No reason provided.",
    }

    lower = reason.lower()

    if reason in bad_reasons:
        return False
    if "invalid json" in lower:
        return False
    if "missing reason field" in lower:
        return False
    if "no json object found" in lower:
        return False
    if "returned invalid json" in lower:
        return False

    return True


def make_assistant_content(*, judgment: str, reason: str) -> str:
    return json.dumps(
        {
            "judgment": normalize_label(judgment),
            "reason": clean_text(reason, max_len=1000),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _first_dict(*values: Any) -> Dict[str, Any]:
    for value in values:
        if isinstance(value, dict) and value:
            return value
    return {}


def _extract_original_io(sample: Dict[str, Any]) -> tuple[str, str]:
    original = _as_dict(sample.get("original_en"))

    attack_prompt = (
        original.get("attack_prompt")
        or sample.get("attack_prompt")
        or sample.get("mutated_prompt")
        or ""
    )

    target_response = (
        original.get("target_response")
        or sample.get("target_response")
        or sample.get("response")
        or ""
    )

    return str(attack_prompt).strip(), str(target_response).strip()


def _extract_nodes(sample: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    benchmark_result 버전별 node key 차이를 흡수한다.
    """
    node_results = _as_dict(sample.get("node_results"))
    debug_nodes = _as_dict(sample.get("debug_nodes"))

    original = _as_dict(sample.get("original_en"))
    original_debug_nodes = _as_dict(original.get("agent_debug_nodes"))

    judge_output = _as_dict(sample.get("judge_output"))
    reason_sources = _as_dict(judge_output.get("reason_sources"))

    evidence = _first_dict(
        node_results.get("evidence_scanner"),
        node_results.get("evidence_scan"),
        node_results.get("evidence_scan_result"),
        judge_output.get("evidence_scan_result"),
        debug_nodes.get("evidence_scanner"),
        debug_nodes.get("evidence_scan_result"),
        original_debug_nodes.get("evidence_scanner"),
        original_debug_nodes.get("evidence_scan_result"),
    )

    strict = _first_dict(
        node_results.get("strict_safe_advocate"),
        node_results.get("strict_auditor"),
        node_results.get("strict_auditor_result"),
        debug_nodes.get("strict_safe_advocate"),
        debug_nodes.get("strict_auditor"),
        debug_nodes.get("strict_auditor_result"),
        original_debug_nodes.get("strict_safe_advocate"),
        original_debug_nodes.get("strict_auditor"),
        original_debug_nodes.get("strict_auditor_result"),
    )

    if not strict and reason_sources.get("safe_side_reason"):
        strict = {
            "judgment": "safe",
            "reason": reason_sources.get("safe_side_reason"),
        }

    context = _first_dict(
        node_results.get("context_vulnerable_advocate"),
        node_results.get("context_auditor"),
        node_results.get("context_auditor_result"),
        debug_nodes.get("context_vulnerable_advocate"),
        debug_nodes.get("context_auditor"),
        debug_nodes.get("context_auditor_result"),
        original_debug_nodes.get("context_vulnerable_advocate"),
        original_debug_nodes.get("context_auditor"),
        original_debug_nodes.get("context_auditor_result"),
    )

    if not context and reason_sources.get("vulnerable_side_reason"):
        context = {
            "judgment": "vulnerable",
            "reason": reason_sources.get("vulnerable_side_reason"),
        }

    consensus = _first_dict(
        node_results.get("consensus"),
        node_results.get("consensus_result"),
        node_results.get("final_consensus"),
        debug_nodes.get("consensus"),
        debug_nodes.get("consensus_result"),
        original_debug_nodes.get("consensus"),
        original_debug_nodes.get("consensus_result"),
    )

    return {
        "evidence": evidence,
        "strict": strict,
        "context": context,
        "consensus": consensus,
    }


def _evidence_summary(evidence: Dict[str, Any]) -> str:
    evidence = _as_dict(evidence)

    summary = {
        "risk": evidence.get("risk", "none"),
        "hard_veto": evidence.get("hard_veto", False),
        "pattern_judgment": evidence.get("pattern_judgment", "ambiguous"),
        "vulnerable_score": evidence.get("vulnerable_score", 0),
        "safe_score": evidence.get("safe_score", 0),
        "vulnerable_conditions": evidence.get("vulnerable_conditions", []),
        "safe_conditions": evidence.get("safe_conditions", []),
        "evidence": evidence.get("evidence", []),
        "excerpts": evidence.get("excerpts", []),
        "classified_evidence": evidence.get("classified_evidence", []),
        "cross_category_tool_calls": evidence.get("cross_category_tool_calls", []),
        "privileged_tool_calls": evidence.get("privileged_tool_calls", []),
        "hidden_metadata_output": evidence.get("hidden_metadata_output", False),
        "execution_claim": evidence.get("execution_claim", False),
        "execution_under_attack": evidence.get("execution_under_attack", False),
        "prompt_copy_detected": evidence.get("prompt_copy_detected", False),
        "quoted_tool_context": evidence.get("quoted_tool_context", False),
        "semantic_echo_detected": evidence.get("semantic_echo_detected", False),
        "structured_tool_call_generated": evidence.get("structured_tool_call_generated", False),
        "tool_call_copied_from_attack": evidence.get("tool_call_copied_from_attack", False),
        "has_reconstruction_intent": evidence.get("has_reconstruction_intent", False),
        "refusal_present": evidence.get("refusal_present", False),
        "compliance_signals": evidence.get("compliance_signals", False),
        "safe_masking": evidence.get("safe_masking", False),
        "safe_analysis_only": evidence.get("safe_analysis_only", False),
        "strong_safe_context": evidence.get("strong_safe_context", False),
        "unsafe_behavior_meaning": evidence.get("unsafe_behavior_meaning", False),
        "internal_config_value_output": evidence.get("internal_config_value_output", False),
    }

    return safe_truncate(
        json.dumps(summary, ensure_ascii=False, separators=(",", ":")),
        max_chars=1600,
    )


def _extract_detail_reason(sample: Dict[str, Any]) -> str:
    judge_output = _as_dict(sample.get("judge_output"))
    reason_sources = _as_dict(judge_output.get("reason_sources"))
    original = _as_dict(sample.get("original_en"))

    return clean_text(
        sample.get("detail")
        or judge_output.get("detail")
        or reason_sources.get("final_reason")
        or reason_sources.get("consensus_reason")
        or original.get("consensus_detail")
        or "",
        max_len=1000,
    )


def _normalized_key_text(text: Any, limit: int = 400) -> str:
    return clean_text(text, max_len=limit).lower()


def _flat_keys(item: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    sample_id = str(item.get("sample_id", "")).strip()
    category = str(item.get("category", "")).strip()
    response_type = str(item.get("response_type", "")).strip()
    return [
        (sample_id, category, response_type),
        (sample_id, "", response_type),
    ]


def build_flattened_reason_index(flattened_data: Any) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """
    benchmark_flattened.json의 정렬된 judgment/reason을 빠르게 찾기 위한 index.
    key: (sample_id, category, response_type)
    value: {judgment, reason, attack_prompt, target_response}
    """
    index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    items = flattened_data
    if isinstance(flattened_data, dict):
        items = (
            flattened_data.get("detailed_results")
            or flattened_data.get("results")
            or flattened_data.get("data")
            or []
        )

    for item in _as_list(items):
        if not isinstance(item, dict):
            continue

        judgment = normalize_label(item.get("judgment") or item.get("expected_judgment"))
        reason = clean_text(item.get("reason", ""), max_len=1000)

        if judgment not in VALID_LABELS or not is_valid_reason(reason):
            continue

        value = {
            "judgment": judgment,
            "reason": reason,
            "attack_prompt_key": _normalized_key_text(item.get("attack_prompt", "")),
            "target_response_key": _normalized_key_text(item.get("target_response", "")),
        }

        for key in _flat_keys(item):
            if key[0] and key[2]:
                index[key] = value

    return index


def _lookup_flattened_reason(
    *,
    sample: Dict[str, Any],
    expected: str,
    attack_prompt: str,
    target_response: str,
    flattened_index: Dict[Tuple[str, str, str], Dict[str, Any]],
) -> tuple[str, str]:
    sample_id = str(sample.get("sample_id", "")).strip()
    category = str(sample.get("category", "")).strip()
    response_type = str(sample.get("response_type", "")).strip()

    candidate_keys = [
        (sample_id, category, response_type),
        (sample_id, "", response_type),
    ]

    for key in candidate_keys:
        item = flattened_index.get(key)
        if not item:
            continue

        if item.get("judgment") != expected:
            continue

        # sample_id + response_type만으로 보통 충분하지만,
        # 혹시 데이터셋이 합쳐진 경우를 대비해 텍스트 prefix도 확인한다.
        flat_attack = str(item.get("attack_prompt_key") or "")
        flat_response = str(item.get("target_response_key") or "")
        attack_key = _normalized_key_text(attack_prompt)
        response_key = _normalized_key_text(target_response)

        attack_ok = not flat_attack or not attack_key or flat_attack[:120] == attack_key[:120]
        response_ok = not flat_response or not response_key or flat_response[:120] == response_key[:120]

        if attack_ok and response_ok:
            return str(item.get("reason") or ""), "flattened.reason"

    return "", "none"


def _select_aligned_reason(
    *,
    expected: str,
    sample: Dict[str, Any],
    attack_prompt: str,
    target_response: str,
    strict: Dict[str, Any],
    context: Dict[str, Any],
    consensus: Dict[str, Any],
    flattened_index: Dict[Tuple[str, str, str], Dict[str, Any]],
) -> tuple[str, str]:
    """
    expected_judgment와 논리적으로 맞는 reason만 선택한다.

    반환:
    - reason
    - reason_source
    """
    flat_reason, flat_source = _lookup_flattened_reason(
        sample=sample,
        expected=expected,
        attack_prompt=attack_prompt,
        target_response=target_response,
        flattened_index=flattened_index,
    )
    if is_valid_reason(flat_reason):
        return flat_reason, flat_source

    consensus_judgment = normalize_label(consensus.get("judgment"))
    consensus_reason = clean_text(consensus.get("reason", ""), max_len=1000)

    strict_reason = clean_text(strict.get("reason", ""), max_len=1000)
    context_reason = clean_text(context.get("reason", ""), max_len=1000)

    detail_reason = _extract_detail_reason(sample)

    if consensus_judgment == expected and is_valid_reason(consensus_reason):
        return consensus_reason, "consensus.reason"

    if is_valid_reason(detail_reason):
        return detail_reason, "sample.detail"

    if expected == "safe" and is_valid_reason(strict_reason):
        return strict_reason, "strict.reason"

    if expected == "vulnerable" and is_valid_reason(context_reason):
        return context_reason, "context.reason"

    return "", "none"


def build_consensus_chat_row(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    reason: str,
    evidence: Dict[str, Any],
    strict: Dict[str, Any],
    context: Dict[str, Any],
    reason_source: str,
    predicted: str,
    is_correct: Optional[bool],
) -> Dict[str, Any]:
    messages = build_consensus_judge_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=target_response,
        evidence=evidence or {},
        strict=strict or {},
        context=context or {},
        evidence_summary=_evidence_summary(evidence or {}),
    )

    return {
        "messages": [
            *messages,
            {
                "role": "assistant",
                "content": make_assistant_content(
                    judgment=judgment,
                    reason=reason,
                ),
            },
        ],
        "meta": {
            "mode": "consensus",
            "category": category,
            "label": normalize_label(judgment),
            "predicted": predicted,
            "is_correct": is_correct,
            "reason_source": reason_source,
        },
    }


# =========================
# PROCESSOR
# =========================

class ConsensusOnlySFTProcessor:
    def __init__(self, flattened_index: Optional[Dict[Tuple[str, str, str], Dict[str, Any]]] = None) -> None:
        self.flattened_index = flattened_index or {}

    def convert(self, raw_json_data: Dict[str, Any]) -> str:
        grouped_samples: Dict[str, List[Dict[str, Any]]] = {
            "vulnerable": [],
            "safe": [],
        }

        stats = {
            "total": 0,
            "skipped_invalid_expected": 0,
            "skipped_missing_io": 0,
            "consensus_added": 0,
            "consensus_skipped_invalid_reason": 0,
            "used_correct_samples": 0,
            "used_wrong_samples": 0,
            "oversampled_rows_added": 0,
            "reason_from_flattened": 0,
            "reason_from_consensus": 0,
            "reason_from_detail": 0,
            "reason_from_strict": 0,
            "reason_from_context": 0,
        }

        detailed_results = raw_json_data.get("detailed_results")
        if detailed_results is None:
            detailed_results = raw_json_data.get("results")

        if detailed_results is None and isinstance(raw_json_data, list):
            detailed_results = raw_json_data

        if detailed_results is None and isinstance(raw_json_data, dict):
            detailed_results = [raw_json_data]

        if not isinstance(detailed_results, list):
            detailed_results = []

        for sample in detailed_results:
            if not isinstance(sample, dict):
                continue

            stats["total"] += 1

            eval_data = _as_dict(sample.get("evaluation"))

            expected = normalize_label(
                eval_data.get("expected_judgment")
                or sample.get("expected_judgment")
                or sample.get("judgment")
            )

            predicted = normalize_label(
                eval_data.get("predicted_judgment")
                or sample.get("predicted_judgment")
            )

            if expected not in VALID_LABELS:
                stats["skipped_invalid_expected"] += 1
                continue

            category = str(sample.get("category") or "LLM01").strip() or "LLM01"
            attack_prompt, target_response = _extract_original_io(sample)

            if not attack_prompt or not target_response:
                stats["skipped_missing_io"] += 1
                continue

            nodes = _extract_nodes(sample)

            evidence = nodes["evidence"]
            strict = nodes["strict"]
            context = nodes["context"]
            consensus = nodes["consensus"]

            reason, reason_source = _select_aligned_reason(
                expected=expected,
                sample=sample,
                attack_prompt=attack_prompt,
                target_response=target_response,
                strict=strict,
                context=context,
                consensus=consensus,
                flattened_index=self.flattened_index,
            )

            if not is_valid_reason(reason):
                stats["consensus_skipped_invalid_reason"] += 1
                continue

            is_correct = None
            if predicted in VALID_LABELS:
                is_correct = expected == predicted

            row = build_consensus_chat_row(
                category=category,
                attack_prompt=attack_prompt,
                target_response=target_response,
                judgment=expected,
                reason=reason,
                evidence=evidence,
                strict=strict,
                context=context,
                reason_source=reason_source,
                predicted=predicted,
                is_correct=is_correct,
            )

            response_type = str(sample.get("response_type", "")).strip()

            repeat = 1

            # vulnerable recall 강화용 oversampling
            # - safe는 1x 유지
            # - 일반 vulnerable은 2x
            # - vulnerable_compliance / vulnerable_data_exposure는 3x
            if expected == "vulnerable":
                repeat = 2

            if response_type in {
                "vulnerable_compliance_response",
                "vulnerable_data_exposure_response",
            }:
                repeat = 2

            for _ in range(repeat):
                grouped_samples[expected].append(row)

            stats["consensus_added"] += repeat
            stats["oversampled_rows_added"] += max(0, repeat - 1)

            if is_correct is True:
                stats["used_correct_samples"] += repeat
            elif is_correct is False:
                stats["used_wrong_samples"] += repeat

            if reason_source == "flattened.reason":
                stats["reason_from_flattened"] += 1
            elif reason_source == "consensus.reason":
                stats["reason_from_consensus"] += 1
            elif reason_source == "sample.detail":
                stats["reason_from_detail"] += 1
            elif reason_source == "strict.reason":
                stats["reason_from_strict"] += 1
            elif reason_source == "context.reason":
                stats["reason_from_context"] += 1

        print("\n[전처리 통계]")
        for key, value in stats.items():
            print(f"{key}: {value}")

        counts = {label: len(items) for label, items in grouped_samples.items()}

        print("\n[라벨 분포]")
        print(f"vulnerable: {counts.get('vulnerable', 0)}")
        print(f"safe: {counts.get('safe', 0)}")

        all_rows = grouped_samples["vulnerable"] + grouped_samples["safe"]

        if not all_rows:
            print("유효 데이터 없음")
            return ""

        random.shuffle(all_rows)

        print(f"\n[최종 학습 샘플 수] {len(all_rows)}")

        return "\n".join(
            json.dumps(row, ensure_ascii=False)
            for row in all_rows
        )


# =========================
# SAVE
# =========================

def load_json_file(file_path: Path) -> Any:
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_sft_file(
    raw_json_data: Dict[str, Any],
    file_path: Path,
    flattened_index: Optional[Dict[Tuple[str, str, str], Dict[str, Any]]] = None,
) -> None:
    processor = ConsensusOnlySFTProcessor(flattened_index=flattened_index)
    sft_content = processor.convert(raw_json_data)

    if sft_content:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(sft_content, encoding="utf-8")
        print(f"\n저장 완료: {file_path}")
    else:
        print("데이터 부족")


# =========================
# MAIN
# =========================

def main() -> None:
    if not INPUT_DATA_PATH.exists():
        print(f"입력 파일 없음: {INPUT_DATA_PATH}")
        return

    try:
        raw_data = load_json_file(INPUT_DATA_PATH)

        flattened_index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        if FLATTENED_DATA_PATH.exists():
            flattened_data = load_json_file(FLATTENED_DATA_PATH)
            flattened_index = build_flattened_reason_index(flattened_data)
            print(f"flattened reason index 로드: {len(flattened_index)}")
        else:
            print(f"flattened 파일 없음, fallback reason 사용: {FLATTENED_DATA_PATH}")

        save_sft_file(
            raw_json_data=raw_data,
            file_path=OUTPUT_DATA_PATH,
            flattened_index=flattened_index,
        )

    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {e}")

    except Exception as e:
        print(f"런타임 오류: {e}")


if __name__ == "__main__":
    main()
