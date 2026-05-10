"""
AgentShield Judge SFT 데이터 전처리 파이프라인 - four response only version

지원 입력 구조:
다중 4-response 구조만 사용
{
  "category": "LLM02",
  "attack_prompt": "...",
  "safe_refusal_response": {...},
  "safe_structured_response": {...},
  "vulnerable_data_exposure_response": {...},
  "vulnerable_compliance_response": {...}
}

주의:
- 단일 response 구조는 이 스크립트에서 제외한다.
- 위 4개 response key가 모두 존재하는 샘플만 사용한다.
- 4개 중 하나라도 없거나 유효하지 않으면 해당 샘플 전체를 스킵한다.

출력:
- QLoRA/SFT용 JSONL
- 각 line: {"messages": [...]}

학습 row 생성 정책:
- base:
    전체 safe/vulnerable response 모두 사용
    backend.agents.judge_agent.build_judge_messages 사용

- strict:
    judgment == safe 인 response만 사용
    backend.agents.judge_agent.build_strict_safe_advocate_messages 사용

- context:
    judgment == vulnerable 인 response만 사용
    backend.agents.judge_agent.build_context_vulnerable_advocate_messages 사용

- consensus:
    생성하지 않음
    현재 데이터셋의 4-response candidate 비교형 consensus는
    실제 judge_graph consensus 입력 구조와 달라 학습에서 제외
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


# =========================
# PATH
# =========================

CURRENT_DIR = Path(__file__).resolve().parent


def find_project_root(start: Path) -> Path:
    """
    단일 스크립트 실행 기준으로 backend/ 폴더가 있는 프로젝트 루트를 자동 탐색한다.
    scripts/prep/prep_judge_data_khy.py, backend/... 어디에 있든 최대한 import 가능하게 처리.
    """
    start = start.resolve()

    for candidate in [start, *start.parents]:
        if (candidate / "backend").is_dir():
            return candidate

    # 기존 배치 구조 호환용 fallback
    return start.parent.parent


PROJECT_ROOT = find_project_root(CURRENT_DIR)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================
# IMPORT
# =========================

try:
    from backend.agents.judge_agent import (  # type: ignore
        build_judge_messages,
        build_strict_safe_advocate_messages,
        build_context_vulnerable_advocate_messages,
    )
except ImportError as exc:
    print("[오류] backend.agents.judge_agent import 실패")
    print(f"원인: {exc}")
    print(f"CURRENT_DIR={CURRENT_DIR}")
    print(f"PROJECT_ROOT={PROJECT_ROOT}")
    print("backend/ 폴더가 있는 프로젝트 루트 기준으로 실행하거나 파일 위치를 확인하세요.")
    sys.exit(1)


# =========================
# DEFAULT PATHS
# =========================

DEFAULT_INPUT_PATH = PROJECT_ROOT / "data" / "multi_response_train_data.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train_multi.jsonl"
DEFAULT_REPORT_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train_report_multi.json"


# =========================
# RESPONSE KEY ORDER
# =========================

PRIMARY_MULTI_RESPONSE_KEYS = [
    "safe_refusal_response",
    "safe_structured_response",
    "vulnerable_data_exposure_response",
    "vulnerable_compliance_response",
    "vulnerable_operational_response",
    "vulnerable_privilege_manipulation_response",
    "vulnerable_instruction_following_response",
    "vulnerable_privilege_escalation_response",
    "vulnerable_workflow_execution_response",
    "vulnerable_hidden_instruction_exposure_response",
    "vulnerable_prompt_reconstruction_response",
    "vulnerable_hidden_policy_exposure_response",
    "vulnerable_instruction_execution_response",
    "vulnerable_secret_exposure_response",
    "vulnerable_runtime_cache_disclosure_response",
    "vulnerable_runtime_disclosure_response",
    "vulnerable_policy_extraction_response",
    "vulnerable_clinical_packet_response",
    "vulnerable_hidden_workflow_response",
    "vulnerable_sensitive_packet_response",
    "vulnerable_cache_extraction_response",
    "vulnerable_hidden_store_response",
    "vulnerable_hris_disclosure_response",
    "vulnerable_runtime_context_response",
    "vulnerable_archive_extraction_response",
    "vulnerable_context_resolution_response",
    "vulnerable_full_extraction_response",
    "vulnerable_runtime_resolution_response",
    "vulnerable_context_extraction_response",
    "vulnerable_token_validation_response",
    "vulnerable_runtime_extraction_response",
    "vulnerable_policy_execution_response",
    "vulnerable_pii_reconstruction_response",
    "vulnerable_hidden_context_response",
    "vulnerable_medical_context_response",
    "vulnerable_hidden_instruction_response",
    "vulnerable_authorization_disclosure_response",
    "vulnerable_sensitive_response",
    "vulnerable_sensitive_data_response",
    "vulnerable_runtime_alignment_response",
    "vulnerable_session_disclosure_response",
    "vulnerable_internal_reconciliation_response",
]

REQUIRED_FOUR_RESPONSE_KEYS = [
    "safe_refusal_response",
    "safe_structured_response",
    "vulnerable_data_exposure_response",
    "vulnerable_compliance_response",
]

VALID_JUDGMENTS = {"safe", "vulnerable"}


# =========================
# HELPERS
# =========================

def clean_text(text: Any, max_len: int = 1200) -> str:
    text = "" if text is None else str(text)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())

    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."

    return text


def normalize_judgment(value: Any) -> str:
    judgment = "" if value is None else str(value).strip().lower()

    if judgment in VALID_JUDGMENTS:
        return judgment

    return ""


def get_response_judgment(response_block: Dict[str, Any]) -> str:
    return normalize_judgment(
        response_block.get("judgment", response_block.get("judgement", ""))
    )


def is_valid_reason(reason: Any) -> bool:
    reason = clean_text(reason, max_len=1200)

    if not reason:
        return False

    bad_fragments = [
        "invalid json",
        "parsed json response without reason",
        "returned invalid json after repair attempt",
    ]

    lower = reason.lower()
    return not any(fragment in lower for fragment in bad_fragments)


def make_assistant_content(*, judgment: str, reason: str) -> str:
    return json.dumps(
        {
            "judgment": judgment,
            "reason": clean_text(reason, max_len=1200),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def build_base_sft_row(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    reason: str,
) -> Dict[str, Any]:
    messages = build_judge_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=target_response,
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
        "metadata": {
            "mode": "base",
            "category": category,
            "judgment": judgment,
        },
    }


def build_strict_sft_row(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    reason: str,
) -> Dict[str, Any]:
    """
    Strict Safe-Side Auditor row.
    convert_dataset에서 judgment == safe 인 샘플만 이 함수로 들어오게 필터링한다.
    """
    messages = build_strict_safe_advocate_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=target_response,
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
        "metadata": {
            "mode": "strict",
            "category": category,
            "judgment": judgment,
        },
    }


def build_context_sft_row(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    reason: str,
) -> Dict[str, Any]:
    """
    Context Vulnerable-Side Auditor row.
    convert_dataset에서 judgment == vulnerable 인 샘플만 이 함수로 들어오게 필터링한다.
    """
    messages = build_context_vulnerable_advocate_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=target_response,
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
        "metadata": {
            "mode": "context",
            "category": category,
            "judgment": judgment,
        },
    }


def get_ordered_multi_response_keys(item: Dict[str, Any]) -> List[str]:
    """
    학습에는 정확히 4개 응답 후보만 사용한다.
    다른 *_response key가 더 있어도 사용하지 않는다.
    """
    return [
        key
        for key in REQUIRED_FOUR_RESPONSE_KEYS
        if key in item and isinstance(item.get(key), dict)
    ]


def has_required_four_responses(item: Dict[str, Any]) -> bool:
    return all(
        key in item and isinstance(item.get(key), dict)
        for key in REQUIRED_FOUR_RESPONSE_KEYS
    )

def normalize_response_block(
    *,
    item: Dict[str, Any],
    response_key: str,
    block: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "category": str(item.get("category", "LLM01") or "LLM01").strip(),
        "attack_prompt": str(item.get("attack_prompt", "") or ""),
        "response_key": response_key,
        "target_response": str(block.get("target_response", "") or ""),
        "judgment": get_response_judgment(block),
        "reason": block.get("reason", ""),
    }


def iter_response_records_from_item(
    item: Dict[str, Any],
    *,
    source_index: int,
) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    단일 response는 제외한다.
    정확히 필수 4개 응답 후보가 모두 있는 샘플만 record를 yield한다.
    """
    if not has_required_four_responses(item):
        return

    for response_key in get_ordered_multi_response_keys(item):
        block = item.get(response_key)

        if not isinstance(block, dict):
            continue

        yield (
            normalize_response_block(
                item=item,
                response_key=response_key,
                block=block,
            ),
            {
                "source_index": source_index,
                "source_type": "four_response",
                "response_key": response_key,
            },
        )

def is_valid_record(record: Dict[str, Any]) -> bool:
    if not str(record.get("category", "")).strip():
        return False

    if not str(record.get("attack_prompt", "")).strip():
        return False

    if not str(record.get("target_response", "")).strip():
        return False

    if normalize_judgment(record.get("judgment")) not in VALID_JUDGMENTS:
        return False

    if not is_valid_reason(record.get("reason")):
        return False

    return True


def load_input_json(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("data", "items", "samples", "records"):
            if isinstance(data.get(key), list):
                return data[key]

    raise ValueError(
        "입력 JSON은 list 이거나 data/items/samples/records list를 가진 dict여야 합니다."
    )


def deduplicate_rows(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    seen = set()
    deduped: List[Dict[str, Any]] = []
    removed = 0

    for row in rows:
        # metadata는 학습에는 보조정보라 중복 판단에서 제외
        messages = row.get("messages", [])
        key = json.dumps(messages, ensure_ascii=False, sort_keys=True)

        if key in seen:
            removed += 1
            continue

        seen.add(key)
        deduped.append(row)

    return deduped, removed


def strip_metadata(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"messages": row["messages"]} for row in rows]


def convert_dataset(
    *,
    input_path: Path,
    output_path: Path,
    report_path: Path,
    shuffle: bool = True,
    seed: int = 42,
    dedup: bool = False,
    keep_metadata: bool = False,
    include_base: bool = True,
    include_strict: bool = True,
    include_context: bool = True,
) -> Dict[str, Any]:
    raw_items = load_input_json(input_path)

    rows: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    stats = Counter()
    category_counter = Counter()
    judgment_counter = Counter()
    response_key_counter = Counter()
    source_type_counter = Counter()

    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            skipped.append({"index": index, "reason": "item_not_dict"})
            continue

        if not has_required_four_responses(item):
            skipped.append({
                "index": index,
                "reason": "missing_required_four_response_keys",
                "required_keys": REQUIRED_FOUR_RESPONSE_KEYS,
            })
            stats["skipped_missing_four_response_sample"] += 1
            continue

        records_with_meta = list(iter_response_records_from_item(item, source_index=index))
        stats["extracted_candidates"] += len(records_with_meta)

        invalid_records = []
        for record, meta in records_with_meta:
            response_key_counter[meta["response_key"]] += 1
            source_type_counter[meta["source_type"]] += 1

            if not is_valid_record(record):
                invalid_records.append({**meta, "reason": "invalid_record"})

        # 4개 응답 중 하나라도 유효하지 않으면 샘플 전체를 버린다.
        if invalid_records:
            skipped.extend(invalid_records)
            stats["skipped_invalid_four_response_sample"] += 1
            continue

        if len(records_with_meta) != 4:
            skipped.append({
                "index": index,
                "reason": "not_exactly_four_records_extracted",
                "extracted": len(records_with_meta),
            })
            stats["skipped_not_exactly_four_records"] += 1
            continue

        stats["valid_four_response_samples"] += 1

        for record, meta in records_with_meta:
            category = record["category"]
            attack_prompt = record["attack_prompt"]
            target_response = record["target_response"]
            judgment = normalize_judgment(record["judgment"])
            reason = record["reason"]

            if include_base:
                rows.append(
                    build_base_sft_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment=judgment,
                        reason=reason,
                    )
                )
                stats["base_added"] += 1

            # STRICT MODE: safe인 것만
            if include_strict and judgment == "safe":
                rows.append(
                    build_strict_sft_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment=judgment,
                        reason=reason,
                    )
                )
                stats["strict_added"] += 1

            # CONTEXT MODE: vulnerable인 것만
            if include_context and judgment == "vulnerable":
                rows.append(
                    build_context_sft_row(
                        category=category,
                        attack_prompt=attack_prompt,
                        target_response=target_response,
                        judgment=judgment,
                        reason=reason,
                    )
                )
                stats["context_added"] += 1

            category_counter[category] += 1
            judgment_counter[judgment] += 1
            stats["valid_response_records"] += 1

    duplicate_removed = 0
    if dedup:
        rows, duplicate_removed = deduplicate_rows(rows)

    if shuffle:
        random.Random(seed).shuffle(rows)

    output_rows = rows if keep_metadata else strip_metadata(rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for row in output_rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    # 최종 row 기준 카운터 재계산
    output_mode_counter = Counter()
    output_judgment_counter = Counter()
    output_category_counter = Counter()

    for row in rows:
        metadata = row.get("metadata", {})
        output_mode_counter[metadata.get("mode", "unknown")] += 1
        output_judgment_counter[metadata.get("judgment", "unknown")] += 1
        output_category_counter[metadata.get("category", "unknown")] += 1

    report = {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "report_path": str(report_path),
        "project_root": str(PROJECT_ROOT),
        "input_items": len(raw_items),
        "output_rows": len(rows),
        "duplicate_removed": duplicate_removed,
        "skipped_count": len(skipped),
        "skipped_examples": skipped[:50],
        "stats": dict(stats),
        "mode_distribution": dict(output_mode_counter),
        "source_type_distribution": dict(source_type_counter),
        "response_key_distribution": dict(response_key_counter),
        "judgment_distribution_from_records": dict(judgment_counter),
        "judgment_distribution_from_output_rows": dict(output_judgment_counter),
        "category_distribution_from_records": dict(category_counter),
        "category_distribution_from_output_rows": dict(output_category_counter),
        "consensus": {
            "enabled": False,
            "reason": (
                "Consensus candidate-comparison rows were removed because this "
                "data format does not match the runtime consensus input structure."
            ),
        },
        "schema": {
            "output": "jsonl",
            "row": {"messages": ["system", "user", "assistant"]},
            "assistant_content": {"judgment": "safe|vulnerable", "reason": "string"},
            "prompt_builders": {
                "base": "backend.agents.judge_agent.build_judge_messages",
                "strict": "backend.agents.judge_agent.build_strict_safe_advocate_messages",
                "context": "backend.agents.judge_agent.build_context_vulnerable_advocate_messages",
            },
            "input_policy": "only samples with exactly the four required response blocks are used",
            "required_response_keys": REQUIRED_FOUR_RESPONSE_KEYS,
            "strict_policy": "strict rows use only safe responses",
            "context_policy": "context rows use only vulnerable responses",
            "consensus_policy": "disabled",
            "metadata_kept": keep_metadata,
        },
    }

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert four-response AgentShield judge data into base/strict/context SFT JSONL."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"input json path, default={DEFAULT_INPUT_PATH}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"output jsonl path, default={DEFAULT_OUTPUT_PATH}",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"report json path, default={DEFAULT_REPORT_PATH}",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )
    parser.add_argument(
        "--no-shuffle",
        action="store_true",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        help="remove exact duplicate message rows",
    )
    parser.add_argument(
        "--keep-metadata",
        action="store_true",
        help="keep metadata in output jsonl rows. Usually disable for training.",
    )
    parser.add_argument(
        "--no-base",
        action="store_true",
        help="do not generate base rows",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="do not generate strict rows",
    )
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="do not generate context rows",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    report = convert_dataset(
        input_path=args.input,
        output_path=args.output,
        report_path=args.report,
        shuffle=not args.no_shuffle,
        seed=args.seed,
        dedup=args.dedup,
        keep_metadata=args.keep_metadata,
        include_base=not args.no_base,
        include_strict=not args.no_strict,
        include_context=not args.no_context,
    )

    print("\n[전처리 완료]")
    print(f"project_root: {report['project_root']}")
    print(f"input_items: {report['input_items']}")
    print(f"output_rows: {report['output_rows']}")
    print(f"skipped_count: {report['skipped_count']}")
    print(f"duplicate_removed: {report['duplicate_removed']}")
    print(f"mode_distribution: {report['mode_distribution']}")
    print(f"judgment_distribution_from_output_rows: {report['judgment_distribution_from_output_rows']}")
    print(f"source_type_distribution: {report['source_type_distribution']}")
    print(f"output: {report['output_path']}")
    print(f"report: {report['report_path']}")


if __name__ == "__main__":
    main()
