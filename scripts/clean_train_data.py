"""
[R1] 학습 데이터 정제 스크립트

judge_train.jsonl (또는 다른 JSONL 학습 데이터)를 정제하여
오염된 데이터를 제거하고 깨끗한 버전을 생성한다.

정제 항목:
  1. 응답이 문장 중간에 잘린 건 제거
  2. 카테고리 오분류 의심 건 재분류 또는 제거
  3. unharmful 라벨인데 유해 내용 포함 의심 건 플래그
  4. 중복 prompt 처리 (같은 질문에 다른 응답 → 1건만 유지 or 유지)
  5. output JSON 유효성 검증

결과 저장:
  results/ 폴더에 타임스탬프로 정제 결과 보고서 저장
  data/finetuning/ 에 정제된 JSONL 파일 저장 (원본 유지, 새 파일 생성)

사용법:
  cd AgentShield
  python scripts/clean_train_data.py                          # 보고서만 (dry-run)
  python scripts/clean_train_data.py --apply                  # 정제 적용, 새 파일 생성
  python scripts/clean_train_data.py --apply --keep-dupes     # 중복 유지
  python scripts/clean_train_data.py --input data/finetuning/some_other.jsonl  # 다른 파일
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "data" / "finetuning" / "judge_train.jsonl"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

# ── 카테고리별 키워드 (오분류 탐지용) ──
CATEGORY_KEYWORDS = {
    "LLM01": ["jailbreak", "ignore", "override", "pretend", "act as",
              "harmful", "violence", "harassment", "discrimination",
              "illegal", "malware", "weapons", "drugs", "terrorism"],
    "LLM02": ["personal", "private", "confidential", "pii", "data",
              "identity", "password", "ssn", "credit card", "phishing",
              "surveillance", "tracking", "doxxing", "leak"],
    "LLM06": ["execute", "tool", "function_call", "api", "database",
              "file", "command", "permission", "authorize", "delete",
              "send", "transfer", "process", "run"],
    "LLM07": ["system prompt", "instructions", "reveal", "configuration",
              "your role", "your rules", "initial prompt", "leak prompt"],
}

# ── 유해 이어짐 패턴 (unharmful 라벨 의심용) ──
HARMFUL_CONTINUATION = [
    "here is", "here are", "here's", "step 1", "step 2",
    "how to", "instructions for", "guide to", "below are",
    "the following", "let me help", "certainly", "sure,",
]


def load_data(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            try:
                item = json.loads(line)
                item["_line_num"] = line_num
                records.append(item)
            except json.JSONDecodeError:
                print(f"  경고: {line_num}번째 줄 JSON 파싱 실패, 건너뜀")
    return records


def parse_input(item: dict) -> tuple[str, str]:
    """input 필드에서 prompt, response 분리"""
    text = item.get("input", "")
    parts = text.split("\n\nResponse: ", 1)
    if len(parts) == 2:
        prompt = parts[0].replace("Prompt: ", "", 1)
        response = parts[1]
        return prompt, response
    return text, ""


def check_truncated(response: str) -> bool:
    """응답이 문장 중간에 잘린 건인지 확인"""
    stripped = response.strip()
    if not stripped:
        return True
    # 정상 종료 문자
    if stripped[-1] in '.!?")\']…':
        return False
    # 이모지로 끝나면 정상
    if ord(stripped[-1]) > 0x1F000:
        return False
    # 숫자로 끝나면 (목록 등) 잘린 것일 수 있음
    return True


def check_category_fit(item: dict, prompt: str) -> str | None:
    """카테고리가 맞는지 확인. 더 적합한 카테고리가 있으면 반환"""
    cat = item["owasp_category"]
    prompt_lower = prompt.lower()

    scores = {}
    for c, keywords in CATEGORY_KEYWORDS.items():
        scores[c] = sum(1 for kw in keywords if kw in prompt_lower)

    best = max(scores, key=scores.get)
    if scores[best] > 0 and best != cat and scores[best] > scores.get(cat, 0):
        return best
    return None


def check_label_suspect(item: dict, response: str) -> bool:
    """unharmful 라벨인데 유해 내용이 포함된 것 같은지"""
    out = json.loads(item["output"])
    if out["response_harm"] != "unharmful" or out["prompt_harm"] != "harmful":
        return False
    if out["refusal"] != "compliance":
        return False
    response_lower = response.lower()[:300]
    matches = sum(1 for p in HARMFUL_CONTINUATION if p in response_lower)
    return matches >= 2


def check_output_valid(item: dict) -> str | None:
    """output JSON 유효성 검증"""
    try:
        out = json.loads(item["output"])
        if "prompt_harm" not in out:
            return "prompt_harm 필드 누락"
        if "response_harm" not in out:
            return "response_harm 필드 누락"
        if "refusal" not in out:
            return "refusal 필드 누락"
        if out["prompt_harm"] not in ("harmful", "unharmful"):
            return f"prompt_harm 값 이상: {out['prompt_harm']}"
        if out["response_harm"] not in ("harmful", "unharmful"):
            return f"response_harm 값 이상: {out['response_harm']}"
        if out["refusal"] not in ("refusal", "compliance"):
            return f"refusal 값 이상: {out['refusal']}"
    except json.JSONDecodeError:
        return "output JSON 파싱 실패"
    return None


def analyze(records: list[dict], keep_dupes: bool = True) -> dict:
    """전체 정제 분석"""

    issues = {
        "truncated": [],        # 잘린 응답
        "misclassified": [],    # 카테고리 오분류
        "label_suspect": [],    # 라벨 의심
        "output_invalid": [],   # output 유효성
        "duplicate_prompts": [],  # 중복 prompt
    }

    prompt_map = defaultdict(list)  # prompt → [index, ...]

    for i, item in enumerate(records):
        prompt, response = parse_input(item)

        # 1. 잘린 응답
        if check_truncated(response):
            issues["truncated"].append({
                "index": i,
                "line": item["_line_num"],
                "category": item["owasp_category"],
                "ending": response.strip()[-50:] if response.strip() else "(빈응답)",
            })

        # 2. 카테고리 오분류
        better_cat = check_category_fit(item, prompt)
        if better_cat:
            issues["misclassified"].append({
                "index": i,
                "line": item["_line_num"],
                "current": item["owasp_category"],
                "suggested": better_cat,
                "prompt_preview": prompt[:100],
            })

        # 3. 라벨 의심
        if check_label_suspect(item, response):
            issues["label_suspect"].append({
                "index": i,
                "line": item["_line_num"],
                "category": item["owasp_category"],
                "response_preview": response[:150],
            })

        # 4. output 유효성
        validity = check_output_valid(item)
        if validity:
            issues["output_invalid"].append({
                "index": i,
                "line": item["_line_num"],
                "issue": validity,
            })

        # 5. 중복 수집
        prompt_map[prompt].append(i)

    # 중복 처리
    for prompt, indices in prompt_map.items():
        if len(indices) > 1:
            issues["duplicate_prompts"].append({
                "prompt_preview": prompt[:100],
                "count": len(indices),
                "indices": indices,
            })

    return issues


def apply_cleaning(records: list[dict], issues: dict, keep_dupes: bool) -> list[dict]:
    """정제 적용 — 문제 건 제거 또는 수정"""

    remove_indices = set()

    # 1. 잘린 응답 → 제거
    for item in issues["truncated"]:
        remove_indices.add(item["index"])

    # 2. output 유효성 실패 → 제거
    for item in issues["output_invalid"]:
        remove_indices.add(item["index"])

    # 3. 카테고리 오분류 → 재분류 (제거하지 않고 카테고리 수정)
    reclass_map = {}
    for item in issues["misclassified"]:
        reclass_map[item["index"]] = item["suggested"]

    # 4. 중복 → keep_dupes=False면 첫 번째만 유지
    if not keep_dupes:
        for item in issues["duplicate_prompts"]:
            for idx in item["indices"][1:]:  # 첫 번째 제외 나머지 제거
                remove_indices.add(idx)

    # 5. 라벨 의심 → 제거 (보안 모델이니 의심스러우면 빼는 게 안전)
    for item in issues["label_suspect"]:
        remove_indices.add(item["index"])

    # 적용
    cleaned = []
    for i, rec in enumerate(records):
        if i in remove_indices:
            continue
        # 카테고리 재분류
        if i in reclass_map:
            rec = dict(rec)  # 원본 보존
            rec["owasp_category"] = reclass_map[i]
        # _line_num 제거 (내부용)
        out = {k: v for k, v in rec.items() if k != "_line_num"}
        cleaned.append(out)

    return cleaned


def save_cleaned(cleaned: list[dict], original_path: Path) -> Path:
    """정제된 데이터를 새 파일로 저장 (원본 유지)"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = original_path.stem
    new_name = f"{stem}_cleaned_{timestamp}.jsonl"
    new_path = original_path.parent / new_name

    with open(new_path, "w", encoding="utf-8") as f:
        for rec in cleaned:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return new_path


def save_report(issues: dict, original_count: int, cleaned_count: int,
                input_path: str, mode: str) -> Path:
    """정제 보고서를 results/ 에 저장"""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = RESULTS_DIR / f"clean_report_{timestamp}.json"

    report = {
        "실행_시각": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "모드": mode,
        "입력_파일": input_path,
        "원본_건수": original_count,
        "정제_후_건수": cleaned_count,
        "제거_건수": original_count - cleaned_count,
        "문제_요약": {
            "잘린_응답": len(issues["truncated"]),
            "카테고리_오분류": len(issues["misclassified"]),
            "라벨_의심": len(issues["label_suspect"]),
            "output_유효성_실패": len(issues["output_invalid"]),
            "중복_prompt_그룹": len(issues["duplicate_prompts"]),
        },
        "상세": {
            "잘린_응답": issues["truncated"],
            "카테고리_오분류": issues["misclassified"],
            "라벨_의심": issues["label_suspect"],
            "output_유효성_실패": issues["output_invalid"],
            "중복_prompt": issues["duplicate_prompts"],
        },
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return filepath


def print_summary(issues: dict, original_count: int, cleaned_count: int):
    """터미널 요약"""
    print(f"\n{'='*60}")
    print(f"데이터 정제 결과 요약")
    print(f"{'='*60}")
    print(f"  원본: {original_count}건")
    print(f"  정제 후: {cleaned_count}건 (제거: {original_count - cleaned_count}건)")
    print()
    print(f"  잘린 응답 (제거): {len(issues['truncated'])}건")
    print(f"  카테고리 오분류 (재분류): {len(issues['misclassified'])}건")
    print(f"  라벨 의심 (제거): {len(issues['label_suspect'])}건")
    print(f"  output 유효성 실패 (제거): {len(issues['output_invalid'])}건")
    print(f"  중복 prompt 그룹: {len(issues['duplicate_prompts'])}건")

    if issues["misclassified"]:
        print(f"\n{'─'*60}")
        print(f"카테고리 재분류 샘플 (처음 5건):")
        for item in issues["misclassified"][:5]:
            print(f"  [{item['current']}→{item['suggested']}] {item['prompt_preview'][:80]}...")

    if issues["label_suspect"]:
        print(f"\n{'─'*60}")
        print(f"라벨 의심 샘플 (처음 5건):")
        for item in issues["label_suspect"][:5]:
            print(f"  [{item['category']}] {item['response_preview'][:80]}...")


def main():
    parser = argparse.ArgumentParser(description="학습 데이터 정제 (judge_train.jsonl)")
    parser.add_argument("--input", type=str, default=str(DEFAULT_INPUT),
                        help="정제할 JSONL 파일 경로")
    parser.add_argument("--apply", action="store_true",
                        help="정제 적용 (새 파일 생성). 없으면 보고서만 출력")
    parser.add_argument("--keep-dupes", action="store_true",
                        help="중복 prompt 유지 (기본: 제거)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"파일 없음: {input_path}")
        sys.exit(1)

    print(f"데이터 로딩: {input_path}")
    records = load_data(input_path)
    print(f"  {len(records)}건 로드 완료")

    print(f"\n정제 분석 중...")
    issues = analyze(records, keep_dupes=args.keep_dupes)

    if args.apply:
        mode = "정제 적용"
        cleaned = apply_cleaning(records, issues, keep_dupes=args.keep_dupes)
        cleaned_path = save_cleaned(cleaned, input_path)
        cleaned_count = len(cleaned)
        print(f"\n정제된 파일: {cleaned_path}")
    else:
        mode = "보고서만 (dry-run)"
        # 제거될 건수 계산
        remove_set = set()
        for item in issues["truncated"]:
            remove_set.add(item["index"])
        for item in issues["output_invalid"]:
            remove_set.add(item["index"])
        for item in issues["label_suspect"]:
            remove_set.add(item["index"])
        if not args.keep_dupes:
            for item in issues["duplicate_prompts"]:
                for idx in item["indices"][1:]:
                    remove_set.add(idx)
        cleaned_count = len(records) - len(remove_set)

    report_path = save_report(issues, len(records), cleaned_count, str(input_path), mode)

    print_summary(issues, len(records), cleaned_count)
    print(f"\n{'='*60}")
    print(f"상세 보고서: {report_path}")
    if not args.apply:
        print(f"\n  실제 정제하려면: python scripts/clean_train_data.py --apply")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
