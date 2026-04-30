import json
import asyncio
import sys
import os
import random
import re
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
OUTPUT_PATH = project_root / "data" / "debug_results_ko.json"

# 번역 설정
NARRATIVE_KEYS = ["detail", "reason"]
MAX_TRANSLATE_CHARS = 2000
GLOBAL_TRANSLATOR = GoogleTranslator(source='en', target='ko')
SEMAPHORE = asyncio.Semaphore(10)

async def translate_text(text: str) -> str:
    """긴 텍스트 분할 및 비동기 번역 처리"""
    if not text or not isinstance(text, str) or text.strip() in ["No detail", ""]:
        return text
    
    async with SEMAPHORE:
        try:
            # 2000자 초과 시 문장 단위 분할 번역
            if len(text) > MAX_TRANSLATE_CHARS:
                sentences = re.split(r'(?<=[.!?])\s+|\n', text)
                chunks, current_chunk = [], ""
                
                for sentence in sentences:
                    if len(current_chunk) + len(sentence) < MAX_TRANSLATE_CHARS:
                        current_chunk += (" " + sentence if current_chunk else sentence)
                    else:
                        if current_chunk:
                            chunks.append(await asyncio.to_thread(GLOBAL_TRANSLATOR.translate, current_chunk))
                        current_chunk = sentence
                        
                if current_chunk:
                    chunks.append(await asyncio.to_thread(GLOBAL_TRANSLATOR.translate, current_chunk))
                return " ".join(chunks)
            
            # 일반 번역
            return await asyncio.to_thread(GLOBAL_TRANSLATOR.translate, text)
        except Exception as e:
            print(f"번역 오류: {e}")
            return text

async def translate_dict_fields(data_dict: dict) -> dict:
    """딕셔너리 내 핵심 내러티브 필드만 추출하여 번역"""
    if not isinstance(data_dict, dict):
        return data_dict
    
    translated_data = data_dict.copy()
    translate_tasks = {}

    # 번역 대상 필터링 및 태스크 매핑
    for key, value in data_dict.items():
        if key in NARRATIVE_KEYS and isinstance(value, str) and value.strip():
            translate_tasks[key] = translate_text(value)
    
    # 병렬 번역 실행 및 매핑
    if translate_tasks:
        keys = list(translate_tasks.keys())
        results = await asyncio.gather(*translate_tasks.values())
        for key, result_text in zip(keys, results):
            translated_data[f"{key}_ko"] = result_text
            
    return translated_data

async def benchmark_judge(dataset_path: Path, output_path: Path, sample_count: int = 10):
    """보안 판정 벤치마크 실행 및 결과 저장 핵심 로직"""
    if not dataset_path.exists():
        print(f"파일 미존재: {dataset_path}")
        return
    
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    # 랜덤 샘플링
    test_samples = random.sample(dataset, min(sample_count, len(dataset)))
    
    metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    results_log = []

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작 (대상: {len(test_samples)}개)\n")

    for i, item in enumerate(test_samples):
        print(f"[{i+1}/{len(test_samples)}] 샘플 판정 및 번역 중...")

        category = item.get("category", "LLM01")
        attack_prompt = item.get("mutated_prompt", "")
        target_response = item.get("target_response", "")
        expected_judgment = item.get("judgment", "safe")

        # 1. 보안 판정 실행
        result = await full_judge(category, attack_prompt, target_response)
        predicted_judgment = result.get("judgment", "ambiguous")
        debug_nodes = result.get("debug_nodes", {})
        consensus_detail = result.get("detail", "No detail")

        # 2. 결과 분석 및 지표 업데이트
        is_correct = (expected_judgment == predicted_judgment)
        if expected_judgment == "vulnerable":
            metrics["TP" if is_correct else "FN"] += 1
        else:
            metrics["TN" if is_correct else "FP"] += 1

        # 3. 비동기 병렬 번역 준비 (순서 보장)
        node_names = [name for name, data in debug_nodes.items() if data]
        node_tasks = [translate_dict_fields(debug_nodes[name]) for name in node_names]
        
        # 필드 태스크를 딕셔너리로 관리하여 언패킹 오류 방지
        field_keys = ["attack", "response", "detail"]
        field_tasks = [
            translate_text(attack_prompt),      # index 0: attack
            translate_text(target_response),    # index 1: response
            translate_text(consensus_detail)    # index 2: detail
        ]
        
        # 모든 번역 동시 대기 (노드 + 필드 명확히 분리)
        all_node_translated = await asyncio.gather(*node_tasks) if node_tasks else []
        all_field_translated = await asyncio.gather(*field_tasks)
        
        # 3-4. 결과 매핑 (명시적 인덱스 접근)
        translated_nodes = dict(zip(node_names, all_node_translated))
        
        # field_keys 순서와 동일하게 매핑
        attack_ko = all_field_translated[0]
        response_ko = all_field_translated[1]
        detail_ko = all_field_translated[2]

        # 4. 로그 엔트리 생성
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
                "attack_prompt": attack_ko,     # 명확하게 매핑됨
                "target_response": response_ko, # 명확하게 매핑됨
                "consensus_detail": detail_ko,  # 명확하게 매핑됨
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
        print(f"  ▶ {status} | 실제: {expected_judgment.upper()} -> 예측: {str(predicted_judgment).upper()}")

    # 5. 최종 리포트 저장
    accuracy = (metrics["TP"] + metrics["TN"]) / len(test_samples) if test_samples else 0
    final_report = {
        "metadata": {
            "model_used": JUDGE_MODEL,
            "total_samples_tested": len(test_samples)
        },
        "performance_summary": {
            "accuracy": f"{accuracy:.2%}",
            "confusion_matrix": metrics
        },
        "detailed_results": results_log
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, ensure_ascii=False, indent=2)
        
    print(f"\n리포트 저장 완료: {output_path.name}")

if __name__ == "__main__":
    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, 1))