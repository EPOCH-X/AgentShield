import json
import asyncio
import sys
import os
import random
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# 1. 환경 설정 및 경로 최적화
load_dotenv()
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.core.judge import full_judge

# 전역 상수 및 설정 관리
JUDGE_MODEL = os.getenv("OLLAMA_JUDGE_MODEL", "unknown_model")
DATA_PATH = project_root / "data" / "검수완료(830개).json"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_PATH = project_root / "data" / f"benchmark_result_en_{TIMESTAMP}.json" # 이름에 en 명시

def save_checkpoint(output_path: Path, metrics: dict, results_log: list, is_final: bool = False):
    """결과 데이터를 JSON으로 저장 (중간 저장 및 최종 저장 통합)"""
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
    """보안 판정 벤치마크 (번역 제거 및 순수 추론 최적화)"""
    if not dataset_path.exists():
        print(f"파일 미존재: {dataset_path}")
        return
    
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    safe_data = [item for item in dataset if item.get("judgment", "").lower() == "safe"]
    vuln_data = [item for item in dataset if item.get("judgment", "").lower() == "vulnerable"]

    sampled_safe = random.sample(safe_data, min(target_per_class, len(safe_data)))
    sampled_vuln = random.sample(vuln_data, min(target_per_class, len(vuln_data)))

    test_samples = sampled_safe + sampled_vuln
    random.shuffle(test_samples)
    
    metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    results_log = []
    total_samples = len(test_samples)

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작 (총 {total_samples}개 샘플)")
    
    try:
        for i, item in enumerate(test_samples):
            category = item.get("category", "LLM01")
            attack_prompt = item.get("mutated_prompt", "")
            target_response = item.get("target_response", "")
            expected_judgment = item.get("judgment", "safe").lower()

            # 판정 수행 (Ollama 집중)
            await asyncio.sleep(0.1)
            result = await full_judge(category, attack_prompt, target_response)
            
            predicted_judgment = result.get("judgment", "ambiguous").lower()
            consensus_detail = result.get("detail", "No detail")
            debug_nodes = result.get("debug_nodes", {})

            is_correct = (expected_judgment == predicted_judgment)
            if expected_judgment == "vulnerable":
                metrics["TP" if is_correct else "FN"] += 1
            else:
                metrics["TN" if is_correct else "FP"] += 1

            log_entry = {
                "sample_id": i + 1,
                "category": category,
                "evaluation": {
                    "is_correct": is_correct,
                    "expected_judgment": expected_judgment,
                    "predicted_judgment": predicted_judgment,
                    "confidence_score": result.get("confidence", 0.0)
                },
                "original_en": {
                    "attack_prompt": attack_prompt,
                    "target_response": target_response,
                    "consensus_detail": consensus_detail,
                    "agent_debug_nodes": debug_nodes
                }
            }
            results_log.append(log_entry)

            status = "[PASS]" if is_correct else "[FAIL]"
            print(f"  ▶ [{i+1}/{total_samples}] {status} | 실제: {expected_judgment.upper()} -> 예측: {str(predicted_judgment).upper()}")
            
            await asyncio.sleep(0.5)

            # 안정성 장치: 10개 처리할 때마다 중간 저장
            if (i + 1) % 10 == 0:
                save_checkpoint(output_path, metrics, results_log, is_final=False)

    except KeyboardInterrupt:
        print("\n[알림] 중단 요청 감지. 현재까지의 데이터를 저장합니다...")
    except Exception as e:
        print(f"\n[오류] 런타임 에러 발생: {e}")
    finally:
        # 최종 리포트 저장
        if results_log:
            save_checkpoint(output_path, metrics, results_log, is_final=True)
            print(f"리포트 최종 저장 완료: {output_path.name}")

if __name__ == "__main__":
    # Windows 비동기 루프 정책 설정
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # 클래스당 250개씩 총 500개 샘플링 설정 유지
    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, target_per_class=250))