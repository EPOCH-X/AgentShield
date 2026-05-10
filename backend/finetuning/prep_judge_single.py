"""
AgentShield SFT 데이터셋 전처리 파이프라인
- benchmark_result.json에서 정답 데이터를 추출
- base / strict_safe_advocate / context_vulnerable_advocate / consensus 프롬프트를 하나의 JSONL에 혼합 저장
- QLoRA 학습용 messages 포맷 생성

중요:
- 학습 입력 프롬프트는 backend.agents.judge_agent의 builder를 그대로 사용한다.
- 즉 실제 judge_agent 런타임 프롬프트와 SFT 데이터 프롬프트가 어긋나지 않도록 한다.

조건:
1. 전체 샘플 필터:
    - expected_judgment와 predicted_judgment가 같은 샘플만 사용

2. base:
    - strict/context 중 expected_judgment와 같은 auditor의 reason만 정답으로 사용
    - 둘 다 같으면 strict reason 하나만 선택
    - 둘 다 아니면 base는 버림

3. strict_safe_advocate:
    - judge_agent의 build_strict_safe_advocate_messages 사용
    - strict 결과가 유효하면 사용
    - 이 builder는 항상 judgment="safe"를 요구하므로 strict 결과도 safe일 때만 사용

4. context_vulnerable_advocate:
    - judge_agent의 build_context_vulnerable_advocate_messages 사용
    - context 결과가 유효하면 사용
    - 이 builder는 항상 judgment="vulnerable"를 요구하므로 context 결과도 vulnerable일 때만 사용

5. consensus:
    - judge_agent의 build_consensus_judge_messages 사용
    - assistant는 {"judgment": expected, "reason": ...} 형태로 저장
    - consensus도 실제 judge_agent처럼 attack_prompt를 untrusted reference로 포함한다.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


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
    from backend.agents.judge_agent import (
        build_context_vulnerable_advocate_messages,
        build_consensus_judge_messages,
        build_judge_messages,
        build_strict_safe_advocate_messages,
    )
except ImportError as e:
    print(f"[오류] judge_agent import 실패: {e}")
    sys.exit(1)


# =========================
# FILE PATH
# =========================

INPUT_DATA_PATH = PROJECT_ROOT / "data" / "benchmark_result_GEMMA4B.json"
OUTPUT_DATA_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train_single.jsonl"

VALID_LABELS = {"vulnerable", "safe"}


# =========================
# HELPERS
# =========================

def clean_text(text: Any, max_len: int = 600) -> str:
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

    return True


def normalize_label(value: Any) -> str:
    return str(value or "").strip().lower()


def make_assistant_content(*, judgment: str, reason: str) -> str:
    return json.dumps(
        {
            "judgment": normalize_label(judgment),
            "reason": clean_text(reason),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_dict(*values: Any) -> Dict[str, Any]:
    for value in values:
        if isinstance(value, dict) and value:
            return value
    return {}


def _get_nested(data: Dict[str, Any], *path: str) -> Any:
    cur: Any = data
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


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

    지원 형태:
    - sample["node_results"]["strict_safe_advocate"]
    - sample["node_results"]["context_vulnerable_advocate"]
    - sample["node_results"]["evidence_scanner"]
    - sample["debug_nodes"]["strict_auditor"]
    - sample["debug_nodes"]["context_auditor"]
    - judge_output.reason_sources fallback
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
        debug_nodes.get("consensus"),
        debug_nodes.get("consensus_result"),
        original_debug_nodes.get("consensus"),
        original_debug_nodes.get("consensus_result"),
    )

    debate = _first_dict(
        node_results.get("debate"),
        node_results.get("debate_result"),
        debug_nodes.get("debate"),
        debug_nodes.get("debate_result"),
        original_debug_nodes.get("debate"),
        original_debug_nodes.get("debate_result"),
    )

    return {
        "evidence": evidence,
        "strict": strict,
        "context": context,
        "consensus": consensus,
        "debate": debate,
    }


def _evidence_summary(evidence: Dict[str, Any]) -> str:
    evidence = _as_dict(evidence)
    summary = {
        "evidence": evidence.get("evidence", []),
        "excerpts": evidence.get("excerpts", []),
        "classified_evidence": evidence.get("classified_evidence", []),
        "cross_category_tool_calls": evidence.get("cross_category_tool_calls", []),
        "privileged_tool_calls": evidence.get("privileged_tool_calls", []),
        "hidden_metadata_output": evidence.get("hidden_metadata_output", False),
        "execution_claim": evidence.get("execution_claim", False),
        "prompt_copy_detected": evidence.get("prompt_copy_detected", False),
        "quoted_tool_context": evidence.get("quoted_tool_context", False),
        "semantic_echo_detected": evidence.get("semantic_echo_detected", False),
        "structured_tool_call_generated": evidence.get("structured_tool_call_generated", False),
        "tool_call_copied_from_attack": evidence.get("tool_call_copied_from_attack", False),
        "has_reconstruction_intent": evidence.get("has_reconstruction_intent", False),
        "refusal_dominant": evidence.get("refusal_dominant", False),
        "compliance_signals": evidence.get("compliance_signals", False),
    }
    return safe_truncate(
        json.dumps(summary, ensure_ascii=False, separators=(",", ":")),
        max_chars=1600,
    )


def _extract_consensus_reason(sample: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> str:
    judge_output = _as_dict(sample.get("judge_output"))
    reason_sources = _as_dict(judge_output.get("reason_sources"))
    original = _as_dict(sample.get("original_en"))
    consensus = _as_dict(nodes.get("consensus"))

    return clean_text(
        judge_output.get("detail")
        or reason_sources.get("final_reason")
        or reason_sources.get("consensus_reason")
        or consensus.get("reason")
        or original.get("consensus_detail")
        or "",
        max_len=1000,
    )


# =========================
# MESSAGE BUILDERS
# =========================

def build_mode_messages(
    *,
    category: str,
    attack_prompt: str,
    response: str,
    mode: str,
    evidence: Optional[Dict[str, Any]] = None,
    strict: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    if mode == "base":
        return build_judge_messages(
            category=category,
            attack_prompt=attack_prompt,
            response=response,
        )

    if mode == "strict":
        return build_strict_safe_advocate_messages(
            category=category,
            attack_prompt=attack_prompt,
            response=response,
        )

    if mode == "context":
        return build_context_vulnerable_advocate_messages(
            category=category,
            attack_prompt=attack_prompt,
            response=response,
        )

    if mode == "consensus":
        return build_consensus_judge_messages(
            category=category,
            attack_prompt=attack_prompt,
            response=response,
            evidence=evidence or {},
            strict=strict or {},
            context=context or {},
            evidence_summary=_evidence_summary(evidence or {}),
        )

    raise ValueError(f"Unknown mode: {mode}")


def build_chat_row(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    reason: str,
    mode: str,
    evidence: Optional[Dict[str, Any]] = None,
    strict: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    messages = build_mode_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=target_response,
        mode=mode,
        evidence=evidence,
        strict=strict,
        context=context,
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
            "mode": mode,
            "category": category,
            "label": normalize_label(judgment),
        },
    }


# =========================
# PROCESSOR
# =========================

class SFTProcessor:
    def convert(self, raw_json_data: Dict[str, Any]) -> str:
        grouped_samples: Dict[str, List[Dict[str, Any]]] = {
            "vulnerable": [],
            "safe": [],
        }

        stats = {
            "total": 0,
            "skipped_invalid_expected": 0,
            "skipped_mismatch": 0,
            "skipped_missing_io": 0,
            "base_added": 0,
            "strict_added": 0,
            "context_added": 0,
            "consensus_added": 0,
            "strict_skipped_invalid_reason": 0,
            "context_skipped_invalid_reason": 0,
            "consensus_skipped_invalid_reason": 0,
            "all_skipped": 0,
        }

        detailed_results = raw_json_data.get("detailed_results")
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
            expected = normalize_label(eval_data.get("expected_judgment") or sample.get("expected_judgment"))
            predicted = normalize_label(eval_data.get("predicted_judgment") or sample.get("predicted_judgment"))

            if expected not in VALID_LABELS:
                stats["skipped_invalid_expected"] += 1
                continue

            # 학습 신뢰도 확보: 최종 예측이 정답과 일치한 샘플만 사용
            if predicted and expected != predicted:
                stats["skipped_mismatch"] += 1
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

            strict_judgment = normalize_label(strict.get("judgment"))
            context_judgment = normalize_label(context.get("judgment"))
            strict_reason = clean_text(strict.get("reason", ""))
            context_reason = clean_text(context.get("reason", ""))

            strict_reason_ok = strict_judgment == expected and is_valid_reason(strict_reason)
            context_reason_ok = context_judgment == expected and is_valid_reason(context_reason)

            rows: List[Dict[str, Any]] = []

            # -------------------------
            # BASE: 일반 judge 프롬프트
            # -------------------------
            if strict_reason_ok:
                base_reason = strict_reason
            elif context_reason_ok:
                base_reason = context_reason
            else:
                base_reason = ""

            if base_reason:
                rows.append(
                    build_chat_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment=expected,
                        reason=base_reason,
                        mode="base",
                    )
                )
                stats["base_added"] += 1

            # -------------------------
            # STRICT SAFE ADVOCATE
            # build_strict_safe_advocate_messages는 항상 safe를 요구한다.
            # 따라서 safe-side 학습은 safe judgment 데이터만 연결한다.
            # -------------------------
            if strict_judgment == "safe" and is_valid_reason(strict_reason):
                rows.append(
                    build_chat_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment="safe",
                        reason=strict_reason,
                        mode="strict",
                    )
                )
                stats["strict_added"] += 1
            elif strict.get("reason") and not is_valid_reason(strict_reason):
                stats["strict_skipped_invalid_reason"] += 1

            # -------------------------
            # CONTEXT VULNERABLE ADVOCATE
            # build_context_vulnerable_advocate_messages는 항상 vulnerable를 요구한다.
            # 따라서 vulnerable-side 학습은 vulnerable judgment 데이터만 연결한다.
            # -------------------------
            if context_judgment == "vulnerable" and is_valid_reason(context_reason):
                rows.append(
                    build_chat_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment="vulnerable",
                        reason=context_reason,
                        mode="context",
                    )
                )
                stats["context_added"] += 1
            elif context.get("reason") and not is_valid_reason(context_reason):
                stats["context_skipped_invalid_reason"] += 1

            # -------------------------
            # CONSENSUS
            # 실제 judge_agent의 build_consensus_judge_messages를 사용한다.
            # assistant도 judge_agent 출력 스키마와 같이 judgment+reason으로 저장한다.
            # -------------------------
            consensus_reason = _extract_consensus_reason(sample, nodes)
            if is_valid_reason(consensus_reason):
                rows.append(
                    build_chat_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment=expected,
                        reason=consensus_reason,
                        mode="consensus",
                        evidence=evidence,
                        strict=strict,
                        context=context,
                    )
                )
                stats["consensus_added"] += 1
            else:
                stats["consensus_skipped_invalid_reason"] += 1

            if not rows:
                stats["all_skipped"] += 1
                continue

            grouped_samples[expected].extend(rows)

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
        print(f"[최종 학습 샘플 수] {len(all_rows)}")

        return "\n".join(json.dumps(row, ensure_ascii=False) for row in all_rows)


# =========================
# SAVE
# =========================

def save_sft_file(raw_json_data: Dict[str, Any], file_path: Path) -> None:
    processor = SFTProcessor()
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
        with INPUT_DATA_PATH.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)

        save_sft_file(raw_data, OUTPUT_DATA_PATH)

    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {e}")

    except Exception as e:
        print(f"런타임 오류: {e}")


if __name__ == "__main__":
    main()
