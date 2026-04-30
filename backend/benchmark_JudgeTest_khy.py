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
# 중복 인스턴스 생성 방지를 위한 전역 번역기
GLOBAL_TRANSLATOR = GoogleTranslator(source='en', target='ko')
# API 과부하 방지를 위한 동시성 제한
SEMAPHORE = asyncio.Semaphore(10)

async def translate_text(text: str) -> str:
    """
    긴 텍스트 분할 및 비동기 번역 처리
    """
    if not text or not isinstance(text, str) or text.strip() in ["No detail", ""]:
        return text
    
    async with SEMAPHORE:
        try:
            # 2000자 초과 시 문장 단위 분할 처리
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
            
            # 일반 번역 (동기 함수를 스레드에서 실행하여 비동기 보장)
            return await asyncio.to_thread(GLOBAL_TRANSLATOR.translate, text)
        except Exception as e:
            print(f"번역 오류: {e}")
            return text

async def translate_dict_fields(data_dict: dict) -> dict:
    """딕셔너리 내 특정 필드(NARRATIVE_KEYS)만 번역하여 구조 유지"""
    if not data_dict:
        return {}
    
    translated_data = data_dict.copy()
    tasks = []
    keys_found = []

    for key, value in data_dict.items():
        if key in NARRATIVE_KEYS and isinstance(value, str):
            keys_found.append(key)
            tasks.append(translate_text(value))
    
    if tasks:
        results = await asyncio.gather(*tasks)
        for key, result in zip(keys_found, results):
            translated_data[f"{key}_ko"] = result
            
    return translated_data

async def benchmark_judge(dataset_path: Path, output_path: Path, sample_count: int = 10):
    """보안 판정 벤치마크 실행 및 결과 저장 핵심 로직"""
    if not dataset_path.exists():
        print(f"파일 미존재: {dataset_path}")
        return
    
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    # 랜덤 샘플링 (중복 방지 및 전체 범위 커버)
    test_samples = random.sample(dataset, min(sample_count, len(dataset)))
    
    metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    results_log = []

    print(f"\n[{JUDGE_MODEL}] 벤치마크 시작 (대상: {len(test_samples)}개)\n")

    for i, item in enumerate(test_samples):
        print(f"[{i+1}/{len(test_samples)}] 샘플 판정 및 번역 중")

        category = item.get("category", "LLM01")
        attack = item.get("mutated_prompt", "")
        response = item.get("target_response", "")
        ground_truth = item.get("judgment", "safe")

        # 1. 보안 판정 실행
        result = await full_judge(category, attack, response)
        pred_judgment = result.get("judgment")
        debug_nodes = result.get("debug_nodes", {})

        # 2. 결과 분석 및 지표 업데이트
        is_correct = (ground_truth == pred_judgment)
        if ground_truth == "vulnerable":
            metrics["TP" if is_correct else "FN"] += 1
        else:
            metrics["TN" if is_correct else "FP"] += 1

        # 3. 비동기 병렬 번역 (에이전트 의견 + 주요 필드)
        node_names = [name for name, data in debug_nodes.items() if data]
        node_tasks = [translate_dict_fields(debug_nodes[name]) for name in node_names]
        
        # 필드 번역 태스크 통합
        field_tasks = [
            translate_text(result.get("detail", "No detail")),
            translate_text(attack),
            translate_text(response)
        ]
        
        # 모든 번역 동시 대기
        all_translated = await asyncio.gather(*(node_tasks + field_tasks))
        
        # 번역 결과 매핑
        translated_nodes = dict(zip(node_names, all_translated[:len(node_names)]))
        detail_ko, attack_ko, response_ko = all_translated[len(node_names):]

        # 4. 로그 엔트리 생성
        log_entry = {
            "index": i + 1,
            "category": category,
            "is_correct": is_correct,
            "actual": ground_truth,
            "pred": pred_judgment,
            "confidence": result.get("confidence", 0.0),
            "detail_ko": detail_ko,
            "agent_opinions_ko": translated_nodes,
            "attack_ko": attack_ko,
            "response_ko": response_ko,
            "original_en": {"attack": attack, "response": response, "detail": result.get("detail")}
        }
        results_log.append(log_entry)

        status = "[PASS]" if is_correct else "[FAIL]"
        print(f"   ▶ [{i+1}/{len(test_samples)}] {status} | {ground_truth.upper()} -> {str(pred_judgment).upper()}")

    # 5. 요약 리포트 저장
    accuracy = (metrics["TP"] + metrics["TN"]) / len(test_samples) if test_samples else 0
    final_report = {
        "summary": {
            "model": JUDGE_MODEL,
            "accuracy": f"{accuracy:.2%}",
            "metrics": metrics
        },
        "details": results_log
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, ensure_ascii=False, indent=2)
        
    print(f"\n리포트 저장 완료: {output_path.name}")

if __name__ == "__main__":
    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH, 100))