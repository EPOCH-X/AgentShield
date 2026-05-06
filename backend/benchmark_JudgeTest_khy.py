import json
import asyncio
import sys
import os
import random
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# 환경 설정
load_dotenv()

current_dir = Path(__file__).parent
project_root = current_dir.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.core.judge import full_judge

# 설정
JUDGE_MODEL = os.getenv("OLLAMA_JUDGE_MODEL", "unknown_model")
DATA_PATH = project_root / "data" / "검수완료(830개).json"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_PATH = project_root / "data" / f"benchmark_result_en_{TIMESTAMP}.json"


def save_checkpoint(output_path: Path, metrics: dict, results_log: list, is_final: bool = False):
    if not results_log:
        return

    accuracy = (metrics["TP"] + metrics["TN"]) / len(results_log)

    report = {
        "metadata": {
            "model_used": JUDGE_MODEL,
            "total_samples_tested": len(results_log),
            "status": "completed" if is_final else "in_progress",
            "timestamp": datetime.now().isoformat()
        },
        "performance_summary": {
            "accuracy": f"{accuracy:.2%}",
            "confusion_matrix": metrics
        },
        "detailed_results": results_log
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


async def benchmark_judge(dataset_path: Path, output_path: Path, target_per_class: int = 75):
    if not dataset_path.exists():
        print(f"파일 미존재: {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    # binary만 유지
    safe_data = [d for d in dataset if d.get("judgment") == "safe"]
    vuln_data = [d for d in dataset if d.get("judgment") == "vulnerable"]

    sampled_safe = random.sample(safe_data, min(target_per_class, len(safe_data)))
    sampled_vuln = random.sample(vuln_data, min(target_per_class, len(vuln_data)))

    test_samples = sampled_safe + sampled_vuln
    random.shuffle(test_samples)

    metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "AMB": 0}
    results_log = []

    total_samples = len(test_samples)

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작 (총 {total_samples}개)")

    try:
        for i, item in enumerate(test_samples):
            category = item.get("category", "LLM01")

            attack_prompt = item.get("mutated_prompt", "")
            target_response = item.get("target_response", "")
            expected = item.get("judgment", "safe")

            # full_judge 내부에서 messages 생성하므로 여기서 만들 필요 없음
            result = await full_judge(
                category=category,
                attack_prompt=attack_prompt,
                response=target_response
            )

            raw_predicted = result.get("judgment", "ambiguous")
            predicted = raw_predicted if raw_predicted in {"safe", "vulnerable"} else "safe"
            
            if raw_predicted not in {"safe", "vulnerable"}:
                metrics["AMB"] += 1

            is_correct = (expected == predicted)

            if expected == "vulnerable":
                metrics["TP" if is_correct else "FN"] += 1
            else:
                metrics["TN" if is_correct else "FP"] += 1

            log_entry = {
                "sample_id": i + 1,
                "category": category,
                "evaluation": {
                    "is_correct": is_correct,
                    "expected_judgment": expected,
                    "predicted_judgment": predicted,
                    "raw_predicted_judgment": raw_predicted,
                    "score": result.get("score", result.get("confidence", 0.0))
                },
                "original_en": {
                    "attack_prompt": attack_prompt,
                    "target_response": target_response,
                    "consensus_detail": result.get("detail", ""),
                    "agent_debug_nodes": result.get("debug_nodes", {})
                }
            }

            results_log.append(log_entry)

            status = "[PASS]" if is_correct else "[FAIL]"
            print(f"▶ [{i+1}/{total_samples}] {status} | GT: {expected.upper()} → PRED: {predicted.upper()}")

            await asyncio.sleep(0.2)

            # checkpoint
            if (i + 1) % 10 == 0:
                save_checkpoint(output_path, metrics, results_log, is_final=False)

    except KeyboardInterrupt:
        print("\n중단됨 - 저장 진행")
    except Exception as e:
        print(f"\n오류: {e}")
    finally:
        if results_log:
            save_checkpoint(output_path, metrics, results_log, is_final=True)
            print(f"\n최종 저장 완료: {output_path.name}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, target_per_class=50))