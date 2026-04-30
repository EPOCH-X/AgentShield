import json
import asyncio
import sys
import os
import random
import re
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

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
OUTPUT_PATH = project_root / "data" / f"benchmark_result_{TIMESTAMP}.json"

# 번역 설정
NARRATIVE_KEYS = ["detail", "reason"]
MAX_TRANSLATE_CHARS = 2000
SEMAPHORE = asyncio.Semaphore(3)

async def translate_text(text: str, max_retries: int = 2) -> str:
    """긴 텍스트 분할 및 비동기 번역 (독립 객체 생성으로 스레드 세이프 보장)"""
    if not text or not isinstance(text, str) or text.strip() in ["No detail", ""]:
        return text
    
    async with SEMAPHORE:
        for attempt in range(max_retries):
            try:
                # 호출 시마다 독립된 번역기 객체를 생성하여 Race Condition 방지
                translator = GoogleTranslator(source='en', target='ko')

                if len(text) > MAX_TRANSLATE_CHARS:
                    sentences = re.split(r'(?<=[.!?])\s+|\n', text)
                    chunks, current_chunk = [], ""
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) < MAX_TRANSLATE_CHARS:
                            current_chunk += (" " + sentence if current_chunk else sentence)
                        else:
                            if current_chunk:
                                chunks.append(await asyncio.to_thread(translator.translate, current_chunk))
                            current_chunk = sentence
                    if current_chunk:
                        chunks.append(await asyncio.to_thread(translator.translate, current_chunk))
                    return " ".join(chunks)
                
                # 단일 문자열 번역
                return await asyncio.to_thread(translator.translate, text)
                
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.5)
                else:
                    print(f"번역 최종 실패: {e}")
                    return text

async def translate_dict_fields(data_dict: dict) -> dict:
    """딕셔너리 내 특정 필드만 추출하여 번역 (키-태스크 명시적 매핑)"""
    if not isinstance(data_dict, dict):
        return data_dict
    
    translated_data = data_dict.copy()
    
    # [최적화] 키 배열과 태스크 배열의 인덱스를 명확히 동기화
    target_keys = [k for k, v in data_dict.items() if k in NARRATIVE_KEYS and isinstance(v, str) and v.strip()]
    
    if target_keys:
        tasks = [translate_text(data_dict[k]) for k in target_keys]
        results = await asyncio.gather(*tasks)
        
        for key, result_text in zip(target_keys, results):
            translated_data[f"{key}_ko"] = result_text
            
    return translated_data

async def benchmark_judge(dataset_path: Path, output_path: Path, target_per_class: int = 75):
    """클래스별 밸런싱(Safe/Vulnerable)을 적용한 보안 판정 벤치마크"""
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

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작")
    print(f"▶ 데이터 구성: 총 {len(test_samples)}개 (Safe: {len(sampled_safe)}개, Vulnerable: {len(sampled_vuln)}개)")
    print("▶ 종료 시 Ctrl+C를 누르면 현재까지의 결과를 저장합니다.\n")

    try:
        for i, item in enumerate(test_samples):
            category = item.get("category", "LLM01")
            attack_prompt = item.get("mutated_prompt", "")
            target_response = item.get("target_response", "")
            expected_judgment = item.get("judgment", "safe")

            result = await full_judge(category, attack_prompt, target_response)
            predicted_judgment = result.get("judgment", "ambiguous")
            debug_nodes = result.get("debug_nodes", {})
            consensus_detail = result.get("detail", "No detail")

            is_correct = (expected_judgment == predicted_judgment)
            if expected_judgment == "vulnerable":
                metrics["TP" if is_correct else "FN"] += 1
            else:
                metrics["TN" if is_correct else "FP"] += 1

            # 비동기 병렬 번역 준비
            node_names = [name for name, data in debug_nodes.items() if data]
            node_tasks = [translate_dict_fields(debug_nodes[name]) for name in node_names]
            
            # [안전장치 유지] 인덱스 고정을 통한 명확한 매핑
            field_tasks = [
                translate_text(attack_prompt),      # index 0: attack
                translate_text(target_response),    # index 1: response
                translate_text(consensus_detail)    # index 2: detail
            ]
            
            all_node_translated = await asyncio.gather(*node_tasks) if node_tasks else []
            all_field_translated = await asyncio.gather(*field_tasks)
            
            translated_nodes = dict(zip(node_names, all_node_translated))
            
            # 인덱스를 통해 1:1 매핑 (데이터 꼬임 원천 차단)
            attack_ko = all_field_translated[0]
            response_ko = all_field_translated[1]
            detail_ko = all_field_translated[2]

            log_entry = {
                "sample_id": i + 1,
                "category": category,
                "evaluation": {
                    "is_correct": is_correct,
                    "expected_judgment": expected_judgment,
                    "predicted_judgment": predicted_judgment,
                    "confidence_score": result.get("confidence", 0.0)
                },
                "translated_ko": {
                    "attack_prompt": attack_ko,
                    "target_response": response_ko,
                    "consensus_detail": detail_ko,
                    "agent_debug_nodes": translated_nodes
                },
                "original_en": {
                    "attack_prompt": attack_prompt,
                    "target_response": target_response,
                    "consensus_detail": consensus_detail
                }
            }
            results_log.append(log_entry)

            status = "[PASS]" if is_correct else "[FAIL]"
            print(f"  ▶ [{i+1}/{len(test_samples)}] {status} | 실제: {expected_judgment.upper()} -> 예측: {str(predicted_judgment).upper()}")

    except asyncio.CancelledError:
        print("\n[알림] 사용자에 의해 벤치마크가 취소되었습니다. 데이터를 저장합니다...")
    except KeyboardInterrupt:
        print("\n[알림] 프로그램 강제 종료 감지. 현재까지의 데이터를 저장합니다...")
    except Exception as e:
        print(f"\n[오류] 벤치마크 중 예기치 않은 오류 발생: {e}")
    finally:
        if results_log:
            accuracy = (metrics["TP"] + metrics["TN"]) / len(results_log)
            final_report = {
                "metadata": {
                    "model_used": JUDGE_MODEL,
                    "total_samples_tested": len(results_log),
                    "distribution": {
                        "safe": len(sampled_safe),
                        "vulnerable": len(sampled_vuln)
                    },
                    "completed_at": datetime.now().isoformat()
                },
                "performance_summary": {
                    "accuracy": f"{accuracy:.2%}",
                    "confusion_matrix": metrics
                },
                "detailed_results": results_log
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, ensure_ascii=False, indent=2)
                
            print(f"리포트 저장 완료: {output_path.name}")
        else:
            print("저장할 테스트 결과가 없습니다.")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, target_per_class=75))
    except KeyboardInterrupt:
        pass