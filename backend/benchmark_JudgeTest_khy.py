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

def translate_text_sync(text: str) -> str:
    """긴 텍스트 분할 및 동기 번역 (데이터 정합성 보장)"""
    if not text or not isinstance(text, str) or text.strip() in ["No detail", ""]:
        return text
    
    try:
        translator = GoogleTranslator(source='en', target='ko')
        
        # 텍스트가 제한 길이를 초과할 경우 분할 처리
        if len(text) > MAX_TRANSLATE_CHARS:
            sentences = re.split(r'(?<=[.!?])\s+|\n', text)
            chunks, current_chunk = [], ""
            
            for sentence in sentences:
                if len(current_chunk) + len(sentence) < MAX_TRANSLATE_CHARS:
                    current_chunk += (" " + sentence if current_chunk else sentence)
                else:
                    if current_chunk:
                        chunks.append(translator.translate(current_chunk))
                    current_chunk = sentence
            
            if current_chunk:
                chunks.append(translator.translate(current_chunk))
            return " ".join(chunks)
        
        return translator.translate(text)
        
    except Exception as e:
        print(f"번역 오류 발생 (원본 유지): {e}")
        return text

def translate_dict_fields_sync(data_dict: dict) -> dict:
    """딕셔너리 내 특정 필드(detail, reason 등) 동기 번역"""
    if not isinstance(data_dict, dict):
        return data_dict
    
    result_dict = data_dict.copy()
    for key in NARRATIVE_KEYS:
        val = data_dict.get(key)
        if val and isinstance(val, str) and val.strip():
            result_dict[f"{key}_ko"] = translate_text_sync(val)
            
    return result_dict

async def benchmark_judge(dataset_path: Path, output_path: Path, target_per_class: int = 75):
    """보안 판정 벤치마크 (번역 단계 동기화로 키 매핑 오류 수정)"""
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

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작 (번역 모드: 동기식)")
    
    try:
        for i, item in enumerate(test_samples):
            category = item.get("category", "LLM01")
            attack_prompt = item.get("mutated_prompt", "")
            target_response = item.get("target_response", "")
            expected_judgment = item.get("judgment", "safe")

            # 판정 수행 (이 부분은 외부 API 호출이므로 비동기 유지)
            result = await full_judge(category, attack_prompt, target_response)
            
            predicted_judgment = result.get("judgment", "ambiguous")
            consensus_detail = result.get("detail", "No detail")
            debug_nodes = result.get("debug_nodes", {})

            is_correct = (expected_judgment == predicted_judgment)
            if expected_judgment == "vulnerable":
                metrics["TP" if is_correct else "FN"] += 1
            else:
                metrics["TN" if is_correct else "FP"] += 1

            # [핵심 수정] 번역을 동기 방식으로 순차 수행 (키 값 꼬임 방지)
            translated_nodes = {}
            for node_name, node_data in debug_nodes.items():
                if node_data:
                    translated_nodes[node_name] = translate_dict_fields_sync(node_data)

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
                    "attack_prompt": translate_text_sync(attack_prompt),
                    "target_response": translate_text_sync(target_response),
                    "consensus_detail": translate_text_sync(consensus_detail),
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

    except KeyboardInterrupt:
        print("\n[알림] 중단 요청 감지. 저장 중...")
    finally:
        if results_log:
            accuracy = (metrics["TP"] + metrics["TN"]) / len(results_log)
            final_report = {
                "metadata": {
                    "model_used": JUDGE_MODEL,
                    "total_samples_tested": len(results_log),
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

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, target_per_class=250))