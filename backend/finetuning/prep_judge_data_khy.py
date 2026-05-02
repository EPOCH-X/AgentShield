"""
AgentShield SFT 데이터셋 전처리 파이프라인
- 역할: 벤치마크 결과에서 정답 데이터를 추출하여 QLoRA 학습용 JSONL로 변환 및 언더샘플링
"""

import json
import sys
import random
from pathlib import Path
from typing import Dict, Any, List

# 동적 경로 설정
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 단일 소스: judge_agent 사용
try:
    from backend.agents.judge_agent import (
        build_judge_messages,
        get_rubric  # (옵션 유지)
    )
except ImportError:
    print("[오류] judge_agent import 실패")
    sys.exit(1)

# 파일 경로
INPUT_DATA_PATH = PROJECT_ROOT / "data" / "benchmark_result.json"
OUTPUT_DATA_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train.jsonl"


class SFTProcessor:
    def convert(self, raw_json_data: Dict[str, Any]) -> str:
        grouped_samples: Dict[str, List[Dict[str, Any]]] = {
            "vulnerable": [],
            "safe": []
        }

        detailed_results = raw_json_data.get("detailed_results", [])

        for sample in detailed_results:
            eval_data = sample.get("evaluation", {})
            expected = eval_data.get("expected_judgment")

            # ambiguous 제거
            if expected not in {"vulnerable", "safe"}:
                continue

            original_data = sample.get("original_en", {})
            nodes = original_data.get("agent_debug_nodes", {})

            strict = nodes.get("strict_auditor", {})
            context = nodes.get("context_auditor", {})

            # 정답 근거 선택
            final_reason = ""
            if strict.get("judgment") == expected:
                final_reason = strict.get("reason", "")
            elif context.get("judgment") == expected:
                final_reason = context.get("reason", "")

            if not final_reason:
                continue

            # 문자열 정리
            final_reason = " ".join(
                final_reason.replace("\n", " ").replace("\r", "").split()
            )

            if len(final_reason) > 600:
                final_reason = final_reason[:597] + "..."

            category = sample.get("category", "LLM01")

            # judge_agent와 동일한 prompt 생성
            messages = build_judge_messages(
                category=category,
                attack_prompt=original_data.get("attack_prompt", ""),
                response=original_data.get("target_response", ""),
            )

            # label JSON (ambiguous 없음)
            assistant_dict = {
                "judgment": expected,
                "confidence": 0.95 if expected == "vulnerable" else 0.05,
                "reason": final_reason,
            }

            assistant_content = json.dumps(
                assistant_dict,
                ensure_ascii=False,
                separators=(",", ":"),
            )

            # messages 구조 완전 동일 + assistant 추가
            chat_row = {
                "messages": [
                    *messages,
                    {"role": "assistant", "content": assistant_content},
                ]
            }

            grouped_samples[expected].append(chat_row)

        # -----------------------------
        # 데이터 밸런싱
        # -----------------------------
        counts = {k: len(v) for k, v in grouped_samples.items() if v}

        if not counts:
            print("유효 데이터 없음")
            return ""

        min_count = min(counts.values())
        print(f"\n[밸런싱] 각 라벨 {min_count}개")

        balanced = []
        for label, items in grouped_samples.items():
            sampled = random.sample(items, min_count)
            balanced.extend(sampled)
            print(f"{label}: {len(items)} → {min_count}")

        random.shuffle(balanced)

        return "\n".join(
            json.dumps(row, ensure_ascii=False)
            for row in balanced
        )


def save_sft_file(raw_json_data: Dict[str, Any], file_path: Path):
    processor = SFTProcessor()
    sft_content = processor.convert(raw_json_data)

    if sft_content:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(sft_content, encoding="utf-8")
        print(f"\n저장 완료: {file_path}")
    else:
        print("데이터 부족")


def main():
    if not INPUT_DATA_PATH.exists():
        print(f"입력 파일 없음: {INPUT_DATA_PATH}")
        return

    try:
        with INPUT_DATA_PATH.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)

        save_sft_file(raw_data, OUTPUT_DATA_PATH)

    except json.JSONDecodeError:
        print("JSON 파싱 오류")
    except Exception as e:
        print(f"런타임 오류: {e}")


if __name__ == "__main__":
    main()