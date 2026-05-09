"""
AgentShield Classifier 데이터 추출 스크립트

목적:
- mixed judge 데이터셋에서 classifier 학습 전용 데이터를 추출
- 학습은 하지 않음
- 출력 데이터는 DeBERTa classifier 학습에 바로 쓰기 좋은 flat 구조

지원 입력 구조:
1) 기존 flat 구조
{
  "mutated_prompt": "...",
  "target_response": "...",
  "judgment": "safe|vulnerable"
}

2) 단일 response 구조
{
  "category": "LLM02",
  "attack_prompt": "...",
  "response": {
    "judgment": "safe|vulnerable",
    "reason": "...",
    "target_response": "..."
  }
}

3) 다중 response 구조
{
  "category": "LLM02",
  "attack_prompt": "...",
  "safe_refusal_response": {...},
  "safe_structured_response": {...},
  "vulnerable_data_exposure_response": {...},
  "vulnerable_compliance_response": {...}
}

출력 JSON 기본 구조:
[
  {
    "category": "LLM02",
    "attack_prompt": "...",
    "target_response": "...",
    "judgment": "safe",
    "label": 0,
    "text": "Prompt: ...\\n\\nResponse: ...",
    "source_type": "single_response|multi_response|flat",
    "response_key": "response|safe_refusal_response|..."
  }
]

label:
- safe = 0
- vulnerable = 1

중요:
- text 필드는 backend.agents.judge_agent.build_classifier_text 와 동일한 형식
  Prompt: {attack_prompt}\\n\\nResponse: {target_response}
"""

from __future__ import annotations

import argparse
import csv
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
    start = start.resolve()

    for candidate in [start, *start.parents]:
        if (candidate / "backend").is_dir():
            return candidate

    return start


PROJECT_ROOT = find_project_root(CURRENT_DIR)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================
# DEFAULT PATHS
# =========================

DEFAULT_INPUT_PATH = PROJECT_ROOT / "data" / "make_train_data.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "finetuning" / "classifier_train_data.json"
DEFAULT_REPORT_PATH = PROJECT_ROOT / "data" / "finetuning" / "classifier_train_data_report.json"


# =========================
# RESPONSE KEYS
# =========================

VALID_JUDGMENTS = {"safe", "vulnerable"}

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


# =========================
# HELPERS
# =========================

def normalize_judgment(value: Any) -> str:
    value = "" if value is None else str(value).strip().lower()

    if value in VALID_JUDGMENTS:
        return value

    return ""


def label_from_judgment(judgment: str) -> int:
    judgment = normalize_judgment(judgment)

    if judgment == "safe":
        return 0

    if judgment == "vulnerable":
        return 1

    raise ValueError(f"invalid judgment: {judgment}")


def build_classifier_text(prompt: str, response: str) -> str:
    return f"Prompt: {prompt or ''}\n\nResponse: {response or ''}"


def get_response_judgment(response_block: Dict[str, Any]) -> str:
    return normalize_judgment(
        response_block.get("judgment", response_block.get("judgement", ""))
    )


def get_ordered_multi_response_keys(item: Dict[str, Any]) -> List[str]:
    keys: List[str] = []
    seen = set()

    for key in PRIMARY_MULTI_RESPONSE_KEYS:
        if key in item and isinstance(item.get(key), dict) and key not in seen:
            keys.append(key)
            seen.add(key)

    for key in sorted(item.keys()):
        if key in seen or key == "response":
            continue

        if key.endswith("_response") and isinstance(item.get(key), dict):
            keys.append(key)
            seen.add(key)

    return keys


def load_json_or_jsonl(path: Path) -> List[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()

    if not raw:
        return []

    if path.suffix.lower() == ".jsonl":
        rows: List[Dict[str, Any]] = []

        for line_no, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL parse error at line {line_no}: {exc}") from exc

            rows.append(obj)

        return rows

    data = json.loads(raw)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("data", "items", "samples", "records"):
            if isinstance(data.get(key), list):
                return data[key]

    raise ValueError(
        "입력은 JSON list, JSONL, 또는 data/items/samples/records list를 가진 dict여야 합니다."
    )


def make_classifier_record(
    *,
    category: str,
    attack_prompt: str,
    target_response: str,
    judgment: str,
    source_type: str,
    response_key: str,
    source_index: int,
    reason: str = "",
) -> Dict[str, Any]:
    judgment = normalize_judgment(judgment)

    return {
        "category": category or "",
        "attack_prompt": attack_prompt or "",
        "target_response": target_response or "",
        "judgment": judgment,
        "label": label_from_judgment(judgment),
        "text": build_classifier_text(attack_prompt or "", target_response or ""),
        "reason": reason or "",
        "source_type": source_type,
        "response_key": response_key,
        "source_index": source_index,
    }


def iter_classifier_records(item: Dict[str, Any], source_index: int) -> Iterable[Dict[str, Any]]:
    """
    item 하나에서 classifier record를 0개 이상 추출한다.
    """

    # 1) 기존 flat 구조
    if "target_response" in item and ("judgment" in item or "judgement" in item):
        attack_prompt = str(
            item.get("attack_prompt")
            or item.get("mutated_prompt")
            or item.get("prompt")
            or ""
        )
        target_response = str(item.get("target_response", "") or "")
        judgment = normalize_judgment(item.get("judgment", item.get("judgement", "")))
        category = str(item.get("category", "") or "")
        reason = str(item.get("reason", "") or "")

        if attack_prompt and target_response and judgment:
            yield make_classifier_record(
                category=category,
                attack_prompt=attack_prompt,
                target_response=target_response,
                judgment=judgment,
                reason=reason,
                source_type="flat",
                response_key="target_response",
                source_index=source_index,
            )
        return

    category = str(item.get("category", "") or "")
    attack_prompt = str(item.get("attack_prompt", "") or "")

    # 2) 단일 response 구조
    response_block = item.get("response")

    if isinstance(response_block, dict) and "target_response" in response_block:
        target_response = str(response_block.get("target_response", "") or "")
        judgment = get_response_judgment(response_block)
        reason = str(response_block.get("reason", "") or "")

        if attack_prompt and target_response and judgment:
            yield make_classifier_record(
                category=category,
                attack_prompt=attack_prompt,
                target_response=target_response,
                judgment=judgment,
                reason=reason,
                source_type="single_response",
                response_key="response",
                source_index=source_index,
            )
        return

    # 3) 다중 response 구조
    for response_key in get_ordered_multi_response_keys(item):
        block = item.get(response_key)

        if not isinstance(block, dict):
            continue

        target_response = str(block.get("target_response", "") or "")
        judgment = get_response_judgment(block)
        reason = str(block.get("reason", "") or "")

        if attack_prompt and target_response and judgment:
            yield make_classifier_record(
                category=category,
                attack_prompt=attack_prompt,
                target_response=target_response,
                judgment=judgment,
                reason=reason,
                source_type="multi_response",
                response_key=response_key,
                source_index=source_index,
            )


def deduplicate_records(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    seen = set()
    deduped: List[Dict[str, Any]] = []
    removed = 0

    for record in records:
        key = (
            record["attack_prompt"],
            record["target_response"],
            record["judgment"],
        )

        if key in seen:
            removed += 1
            continue

        seen.add(key)
        deduped.append(record)

    return deduped, removed


def balance_records(records: List[Dict[str, Any]], seed: int = 42) -> List[Dict[str, Any]]:
    by_label = {0: [], 1: []}

    for record in records:
        by_label[int(record["label"])].append(record)

    min_count = min(len(by_label[0]), len(by_label[1]))

    if min_count <= 0:
        return records

    rng = random.Random(seed)
    balanced: List[Dict[str, Any]] = []

    for label in (0, 1):
        rows = by_label[label][:]
        rng.shuffle(rows)
        balanced.extend(rows[:min_count])

    rng.shuffle(balanced)

    return balanced


def strip_reason(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stripped = []

    for record in records:
        row = dict(record)
        row.pop("reason", None)
        stripped.append(row)

    return stripped


def write_output(records: List[Dict[str, Any]], output_path: Path, output_format: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_format = output_format.lower().strip()

    if output_format == "json":
        output_path.write_text(
            json.dumps(records, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return

    if output_format == "jsonl":
        with output_path.open("w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        return

    if output_format == "csv":
        fieldnames = [
            "category",
            "attack_prompt",
            "target_response",
            "judgment",
            "label",
            "text",
            "reason",
            "source_type",
            "response_key",
            "source_index",
        ]

        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                writer.writerow({key: record.get(key, "") for key in fieldnames})

        return

    raise ValueError("output_format은 json/jsonl/csv 중 하나여야 합니다.")


def extract_classifier_data(
    *,
    input_path: Path,
    output_path: Path,
    report_path: Path,
    output_format: str = "json",
    dedup: bool = True,
    balance: bool = False,
    shuffle: bool = True,
    seed: int = 42,
    include_reason: bool = True,
) -> Dict[str, Any]:
    raw_items = load_json_or_jsonl(input_path)

    records: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            skipped.append({"index": index, "reason": "item_not_dict"})
            continue

        before = len(records)

        for record in iter_classifier_records(item, source_index=index):
            records.append(record)

        if before == len(records):
            skipped.append({"index": index, "reason": "no_valid_record"})

    extracted_before_dedup = len(records)

    duplicate_removed = 0

    if dedup:
        records, duplicate_removed = deduplicate_records(records)

    count_after_dedup = len(records)

    if balance:
        records = balance_records(records, seed=seed)

    if shuffle:
        random.Random(seed).shuffle(records)

    if not include_reason:
        records = strip_reason(records)

    write_output(records, output_path, output_format=output_format)

    report = {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "report_path": str(report_path),
        "output_format": output_format,
        "raw_items": len(raw_items),
        "extracted_before_dedup": extracted_before_dedup,
        "records": len(records),
        "count_after_dedup_before_balance": count_after_dedup,
        "duplicate_removed": duplicate_removed,
        "balance": balance,
        "shuffle": shuffle,
        "seed": seed,
        "include_reason": include_reason,
        "skipped_count": len(skipped),
        "skipped_examples": skipped[:50],
        "judgment_distribution": dict(Counter(record["judgment"] for record in records)),
        "label_distribution": dict(Counter(str(record["label"]) for record in records)),
        "category_distribution": dict(Counter(record.get("category", "") for record in records)),
        "source_type_distribution": dict(Counter(record["source_type"] for record in records)),
        "response_key_distribution": dict(Counter(record["response_key"] for record in records)),
        "schema": {
            "category": "str",
            "attack_prompt": "str",
            "target_response": "str",
            "judgment": "safe|vulnerable",
            "label": "0=safe, 1=vulnerable",
            "text": "Prompt: {attack_prompt}\\n\\nResponse: {target_response}",
            "reason": "optional str",
            "source_type": "flat|single_response|multi_response",
            "response_key": "str",
            "source_index": "int",
        },
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return report


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract classifier-only train data from mixed AgentShield judge data."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"input json/jsonl path, default={DEFAULT_INPUT_PATH}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"output path, default={DEFAULT_OUTPUT_PATH}",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"report path, default={DEFAULT_REPORT_PATH}",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="output format",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-dedup", action="store_true")
    parser.add_argument("--balance", action="store_true")
    parser.add_argument("--no-shuffle", action="store_true")
    parser.add_argument("--no-reason", action="store_true")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    report = extract_classifier_data(
        input_path=args.input,
        output_path=args.output,
        report_path=args.report,
        output_format=args.format,
        dedup=not args.no_dedup,
        balance=args.balance,
        shuffle=not args.no_shuffle,
        seed=args.seed,
        include_reason=not args.no_reason,
    )

    print("\n[classifier 데이터 추출 완료]")
    print(f"input: {report['input_path']}")
    print(f"output: {report['output_path']}")
    print(f"report: {report['report_path']}")
    print(f"raw_items: {report['raw_items']}")
    print(f"extracted_before_dedup: {report['extracted_before_dedup']}")
    print(f"records: {report['records']}")
    print(f"duplicate_removed: {report['duplicate_removed']}")
    print(f"judgment_distribution: {report['judgment_distribution']}")
    print(f"source_type_distribution: {report['source_type_distribution']}")


if __name__ == "__main__":
    main()
