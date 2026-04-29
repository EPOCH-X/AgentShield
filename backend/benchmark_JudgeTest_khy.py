import json
import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

import argostranslate.package
import argostranslate.translate

# 1. 환경 설정 및 경로 최적화
load_dotenv()
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.core.judge import full_judge

# 전역 상수 관리 (변수명 통일)
JUDGE_MODEL = os.getenv("OLLAMA_JUDGE_MODEL", "unknown_model")
DATA_PATH = project_root / "data" / "검수완료(830개).json"
# 모델명을 포함한 동적 출력 경로 설정
OUTPUT_PATH = project_root / "data" / f"debug_results_ko.json"

# 번역이 필요한 긴 문장 키값 정의
NARRATIVE_KEYS = ["detail", "reason"]

def setup_translator(from_code="en", to_code="ko"):
    """Argos Translate 영-한 모델 자동 설치 및 초기화"""
    print(f"번역 엔진({from_code}->{to_code}) 초기화 중...")
    try:
        argostranslate.package.update_package_index()
        available_packages = argostranslate.package.get_available_packages()
        
        package_to_install = next(
            filter(lambda x: x.from_code == from_code and x.to_code == to_code, available_packages), 
            None
        )

        if package_to_install:
            installed = argostranslate.package.get_installed_packages()
            if not any(p.from_code == from_code and p.to_code == to_code for p in installed):
                print(f"모델 다운로드 중...")
                argostranslate.package.install_from_path(package_to_install.download())
                print("설치 완료.")
    except Exception as e:
        print(f"번역 엔진 설정 실패: {e}")

def translate_text(text: str) -> str:
    """영문 텍스트 번역 (예외 발생 시 원문 보존)"""
    if not text or text in ["No detail", ""]:
        return text
    try:
        return argostranslate.translate.translate(text, "en", "ko")
    except Exception:
        return text

def translate_narrative_fields(data_dict: dict) -> dict:
    """딕셔너리 내 NARRATIVE_KEYS에 해당하는 필드만 한국어로 번역하여 추가"""
    translated_data = {}
    for key, value in data_dict.items():
        translated_data[key] = value # 원본 보존
        if key in NARRATIVE_KEYS and isinstance(value, str):
            translated_data[f"{key}_ko"] = translate_text(value)
    return translated_data

async def benchmark_judge(dataset_path: Path, output_path: Path):
    setup_translator()

    if not dataset_path.exists():
        print(f"파일을 찾을 수 없습니다: {dataset_path}")
        return
    
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    test_samples = dataset[:1]
    metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    results_log = []

    print(f"\n[{JUDGE_MODEL}] 심층 판정 테스트 시작-{len(test_samples)}개\n")

    for i, item in enumerate(test_samples):
        category = item.get("category", "LLM01")
        attack = item.get("mutated_prompt", "")
        response = item.get("target_response", "")
        ground_truth = item.get("judgment", "safe")

        print(f"[{i+1}/{len(test_samples)}] 판정 및 번역 진행 중...")

        # 1. 판정 실행
        result = await full_judge(category, attack, response)
        
        pred_judgment = result.get("judgment")
        raw_detail = result.get("detail", "No detail")
        debug_nodes = result.get("debug_nodes", {})

        # 2. 번역 프로세스 (중복 제거 루프)
        # 에이전트별 의견 자동 번역 처리
        agent_opinions_ko = {
            node_name: translate_narrative_fields(node_data)
            for node_name, node_data in debug_nodes.items()
            if node_data
        }

        # 3. 지표 계산 최적화
        is_correct = (ground_truth == pred_judgment)
        if ground_truth == "vulnerable":
            metrics["TP" if is_correct else "FN"] += 1
        else:
            metrics["TN" if is_correct else "FP"] += 1
            
        # 4. 결과 로그 생성
        log_entry = {
            "index": i + 1,
            "category": category,
            "actual": ground_truth,
            "pred": pred_judgment,
            "is_correct": is_correct,
            "confidence": result.get("confidence", 0.0),
            "detail_en": raw_detail,
            "detail_ko": translate_text(raw_detail),
            "agent_opinions_ko": agent_opinions_ko,
            "original_attack": attack,
            "target_response": response
        }
        results_log.append(log_entry)

        status = "[PASS]" if is_correct else "[FAIL]"
        print(f"   └ {status} 실제: {ground_truth[:3].upper()} -> 예측: {str(pred_judgment)[:3].upper()}")

    # 5. 최종 리포트 및 저장
    accuracy = (metrics["TP"] + metrics["TN"]) / len(test_samples)
    summary = {
        "summary": {
            "model": JUDGE_MODEL,
            "accuracy": accuracy,
            "metrics": metrics
        },
        "detailed_results": results_log
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        
    print(f"\n분석 완료: '{output_path.name}' 저장 성공.")

if __name__ == "__main__":
    asyncio.run(benchmark_judge(DATA_PATH, OUTPUT_PATH))