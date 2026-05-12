import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.judge import full_judge

DATA_PATH = PROJECT_ROOT / "data" / "benchmark_flattened.json"

RESULT_PATH = PROJECT_ROOT / "data" / "benchmark_result.json"

WRONG_CASE_PATH = (
    PROJECT_ROOT / "data" / "benchmark_wrong_cases.json"
)

SAVE_EVERY = 5

def save_partial_results(
    *,
    results,
    total,
    correct,
    safe_total,
    safe_correct,
    vulnerable_total,
    vulnerable_correct,
):
    accuracy = (
        correct / total
        if total else 0.0
    )

    safe_accuracy = (
        safe_correct / safe_total
        if safe_total else 0.0
    )

    vulnerable_accuracy = (
        vulnerable_correct
        / vulnerable_total
        if vulnerable_total
        else 0.0
    )

    summary = {
        "total": total,
        "correct": correct,
        "accuracy": round(
            accuracy,
            4,
        ),

        "safe_total": safe_total,
        "safe_correct": safe_correct,
        "safe_accuracy": round(
            safe_accuracy,
            4,
        ),

        "vulnerable_total": vulnerable_total,
        "vulnerable_correct": vulnerable_correct,
        "vulnerable_accuracy": round(
            vulnerable_accuracy,
            4,
        ),
    }

    wrong_results = [
        r for r in results
        if not r["is_correct"]
    ]

    benchmark_output = {
        "summary": summary,
        "results": results,
        "wrong_cases": wrong_results,
    }

    RESULT_PATH.write_text(
        json.dumps(
            benchmark_output,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    WRONG_CASE_PATH.write_text(
        json.dumps(
            wrong_results,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"\n[SAVED] "
        f"{total} rows processed"
    )

async def run_benchmark(data_path):
    data = json.loads(
        Path(data_path).read_text(
            encoding="utf-8"
        )
    )

    results = []

    total = 0
    correct = 0

    safe_total = 0
    safe_correct = 0

    vulnerable_total = 0
    vulnerable_correct = 0

    for row_idx, row in enumerate(data):
        category = row["category"]

        attack_prompt = row[
            "attack_prompt"
        ]

        target_response = row[
            "target_response"
        ]

        expected = row["judgment"]

        response_type = row.get(
            "response_type",
            "unknown",
        )

        judge_result = await full_judge(
            category=category,
            attack_prompt=attack_prompt,
            response=target_response,
            include_debug=True,
        )

        predicted = judge_result.get(
            "judgment",
            "ambiguous",
        )

        is_correct = (
            expected == predicted
        )

        total += 1
        correct += int(is_correct)

        if expected == "safe":
            safe_total += 1
            safe_correct += int(is_correct)

        elif expected == "vulnerable":
            vulnerable_total += 1
            vulnerable_correct += int(is_correct)

        result_row = {
            "row_id": row_idx,
            "sample_id": row.get(
                "sample_id",
            ),
            "category": category,
            "response_type": response_type,
            "expected_judgment": expected,
            "predicted_judgment": predicted,
            "is_correct": is_correct,

            "p_vulnerable": round(
                float(
                    judge_result.get(
                        "p_vulnerable",
                        0.5,
                    )
                ),
                6,
            ),

            "p_safe": round(
                float(
                    judge_result.get(
                        "p_safe",
                        0.5,
                    )
                ),
                6,
            ),

            "matched_patterns": (
                judge_result.get(
                    "matched_patterns",
                    [],
                )
            ),

            "detail": judge_result.get(
                "detail",
                "",
            ),

            "node_results": (
                judge_result.get(
                    "node_results",
                    {},
                )
            ),
        }

        results.append(result_row)
        
        if (
            (row_idx + 1) % SAVE_EVERY == 0
        ):
            save_partial_results(
                results=results,
                total=total,
                correct=correct,
                safe_total=safe_total,
                safe_correct=safe_correct,
                vulnerable_total=vulnerable_total,
                vulnerable_correct=vulnerable_correct,
            )

        # =================================================
        # Terminal debug
        # =================================================

        print("=" * 80)

        print(
            f"[{row_idx}] "
            f"{response_type}"
        )

        print(
            f"EXPECTED : {expected}"
        )

        print(
            f"PREDICTED: {predicted}"
        )

        print(
            f"CORRECT  : {is_correct}"
        )

        print(
            f"P(vuln)="
            f"{judge_result.get('p_vulnerable')} "
            f"P(safe)="
            f"{judge_result.get('p_safe')}"
        )

        if not is_correct:
            print(
                "\n--- WRONG CASE DEBUG ---"
            )

            node_results = (
                judge_result.get(
                    "node_results",
                    {},
                )
            )

            evidence = (
                node_results.get(
                    "evidence_scanner",
                    {},
                )
            )

            consensus = (
                node_results.get(
                    "consensus",
                    {},
                )
            )

            print(
                "RISK:",
                evidence.get("risk"),
            )

            print(
                "HARD_VETO:",
                evidence.get(
                    "hard_veto"
                ),
            )

            print(
                "VULNERABLE_CONDITIONS:",
                evidence.get(
                    "vulnerable_conditions"
                ),
            )

            print(
                "SAFE_CONDITIONS:",
                evidence.get(
                    "safe_conditions"
                ),
            )

            print(
                "EXCERPTS:",
                evidence.get(
                    "excerpts"
                ),
            )

            print(
                "LLM_REASON:",
                evidence.get(
                    "llm_reason"
                ),
            )

            print(
                "CONSENSUS_REASON:",
                consensus.get(
                    "reason"
                ),
            )

        print()

    accuracy = (
        correct / total
        if total else 0.0
    )

    safe_accuracy = (
        safe_correct / safe_total
        if safe_total else 0.0
    )

    vulnerable_accuracy = (
        vulnerable_correct
        / vulnerable_total
        if vulnerable_total
        else 0.0
    )

    summary = {
        "total": total,
        "correct": correct,
        "accuracy": round(
            accuracy,
            4,
        ),

        "safe_total": safe_total,
        "safe_correct": safe_correct,
        "safe_accuracy": round(
            safe_accuracy,
            4,
        ),

        "vulnerable_total": vulnerable_total,
        "vulnerable_correct": vulnerable_correct,
        "vulnerable_accuracy": round(
            vulnerable_accuracy,
            4,
        ),
    }

    wrong_results = [
        r for r in results
        if not r["is_correct"]
    ]
    
    save_partial_results(
        results=results,
        total=total,
        correct=correct,
        safe_total=safe_total,
        safe_correct=safe_correct,
        vulnerable_total=vulnerable_total,
        vulnerable_correct=vulnerable_correct,
    )

    return {
        "summary": summary,
        "results": results,
        "wrong_cases": wrong_results,
    }


async def main():
    benchmark_output = (
        await run_benchmark(
            DATA_PATH
        )
    )

    RESULT_PATH.write_text(
        json.dumps(
            benchmark_output,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    WRONG_CASE_PATH.write_text(
        json.dumps(
            benchmark_output[
                "wrong_cases"
            ],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n")
    print("=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)

    print(
        json.dumps(
            benchmark_output[
                "summary"
            ],
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())