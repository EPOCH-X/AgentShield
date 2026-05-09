import json
import asyncio
import sys
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
DATA_PATH = project_root / "data" / "검수완료(830개).json"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_PATH = project_root / "data" / f"benchmark_result_probability_{TIMESTAMP}.json"


def _safe_float(value, default: float = 0.5) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def save_checkpoint(
    output_path: Path,
    metrics: dict,
    results_log: list,
    is_final: bool = False,
):
    if not results_log:
        return

    evaluated = metrics["TP"] + metrics["TN"] + metrics["FP"] + metrics["FN"]
    total = len(results_log)

    accuracy = (
        (metrics["TP"] + metrics["TN"]) / evaluated
        if evaluated > 0
        else 0.0
    )

    ambiguous_rate = metrics["AMB"] / total if total > 0 else 0.0

    report = {
        "metadata": {
            "total_samples_tested": total,
            "evaluated_samples": evaluated,
            "ambiguous_samples": metrics["AMB"],
            "status": "completed" if is_final else "in_progress",
            "timestamp": datetime.now().isoformat(),
        },
        "performance_summary": {
            "accuracy_excluding_ambiguous": f"{accuracy:.2%}",
            "ambiguous_rate": f"{ambiguous_rate:.2%}",
            "confusion_matrix": metrics,
        },
        "detailed_results": results_log,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


async def benchmark_judge(
    dataset_path: Path,
    output_path: Path,
    target_per_class: int = 75,
):
    if not dataset_path.exists():
        print(f"파일 미존재: {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    safe_data = [
        item for item in dataset
        if str(item.get("judgment", "")).strip().lower() == "safe"
    ]

    vuln_data = [
        item for item in dataset
        if str(item.get("judgment", "")).strip().lower() == "vulnerable"
    ]

    sampled_safe = random.sample(
        safe_data,
        min(target_per_class, len(safe_data)),
    )

    sampled_vuln = random.sample(
        vuln_data,
        min(target_per_class, len(vuln_data)),
    )

    test_samples = sampled_safe + sampled_vuln
    random.shuffle(test_samples)

    metrics = {
        "TP": 0,
        "FP": 0,
        "TN": 0,
        "FN": 0,
        "AMB": 0,
    }

    results_log = []
    total_samples = len(test_samples)

    print(f"\n[Probability Judge Benchmark] 시작 (총 {total_samples}개)")
    print(f"- safe samples: {len(sampled_safe)}")
    print(f"- vulnerable samples: {len(sampled_vuln)}")

    try:
        for i, item in enumerate(test_samples):
            category = item.get("category", "LLM01")
            attack_prompt = item.get("mutated_prompt", "")
            target_response = item.get("target_response", "")
            expected = str(item.get("judgment", "safe")).strip().lower()

            result = await full_judge(
                category=category,
                attack_prompt=attack_prompt,
                response=target_response,
                include_debug=False,
            )

            predicted = str(
                result.get("judgment", "ambiguous")
            ).strip().lower()

            p_vulnerable = _safe_float(
                result.get("p_vulnerable"),
                default=0.5,
            )

            p_safe = _safe_float(
                result.get("p_safe"),
                default=0.5,
            )

            is_ambiguous = predicted not in {"safe", "vulnerable"}

            if is_ambiguous:
                metrics["AMB"] += 1
                is_correct = False

            else:
                is_correct = expected == predicted

                if expected == "vulnerable":
                    metrics["TP" if is_correct else "FN"] += 1
                else:
                    metrics["TN" if is_correct else "FP"] += 1

            log_entry = {
                "sample_id": i + 1,

                "category": result.get("category", category),

                "evaluation": {
                    "is_correct": is_correct,
                    "is_ambiguous": is_ambiguous,

                    "expected_judgment": expected,
                    "predicted_judgment": predicted,

                    "probability_judgment": result.get(
                        "probability_judgment",
                        "",
                    ),

                    "consensus_judgment": result.get(
                        "consensus_judgment",
                        "",
                    ),

                    "judgment_alignment": result.get(
                        "judgment_alignment",
                        "",
                    ),

                    "p_vulnerable": p_vulnerable,
                    "p_safe": p_safe,
                },

                "matched_patterns": result.get(
                    "matched_patterns",
                    [],
                ),

                "original_en": {
                    "attack_prompt": attack_prompt,
                    "target_response": target_response,
                },

                "judge_output": {
                    "detail": result.get("detail", ""),

                    "reason_sources": result.get(
                        "reason_sources",
                        {},
                    ),

                    "mitre_technique_id": result.get(
                        "mitre_technique_id",
                        "",
                    ),
                },

                "node_results": result.get(
                    "node_results",
                    {},
                ),
            }
            results_log.append(log_entry)

            status = (
                "[AMB]"
                if is_ambiguous
                else "[PASS]"
                if is_correct
                else "[FAIL]"
            )

            print(
                f"▶ [{i + 1}/{total_samples}] {status} | "
                f"GT: {expected.upper()} → "
                f"PRED: {predicted.upper()} | "
                f"CONS: {result.get('consensus_judgment', '').upper()} | "
                f"ALIGN: {result.get('judgment_alignment', '').upper()} | "
                f"p_vuln={p_vulnerable:.4f}, "
                f"p_safe={p_safe:.4f}"
            )

            await asyncio.sleep(0.2)

            if (i + 1) % 5 == 0:
                save_checkpoint(
                    output_path,
                    metrics,
                    results_log,
                    is_final=False,
                )

    except KeyboardInterrupt:
        print("\n중단됨 - 저장 진행")

    except Exception as e:
        print(f"\n오류: {e}")

    finally:
        if results_log:
            save_checkpoint(
                output_path,
                metrics,
                results_log,
                is_final=True,
            )

            print(f"\n최종 저장 완료: {output_path.name}")
            print(f"경로: {output_path}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsSelectorEventLoopPolicy()
        )

    asyncio.run(
        benchmark_judge(
            DATA_PATH,
            OUTPUT_PATH,
            target_per_class=5,
        )
    )