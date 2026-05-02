# test_model_eval.py
import torch
import sys
import json
from pathlib import Path
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from typing import Iterator, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from backend.agents.judge_agent import build_judge_messages

def load_test_data(file_path: Path) -> Iterator[Dict[str, str]]:
    """JSON 파일에서 attack_prompt와 target_response를 메모리 효율적으로 추출합니다."""
    if not file_path.exists():
        raise FileNotFoundError(f"[오류] 데이터 파일을 찾을 수 없습니다: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        raw_data = json.load(f)

    for sample in raw_data.get("detailed_results", []):
        category = sample.get("category")
        original_data = sample.get("original_en", {})
        attack_prompt = original_data.get("attack_prompt", "").strip()
        target_response = original_data.get("target_response", "").strip()

        if attack_prompt and target_response:
            yield {
                "category": category,
                "attack_prompt": attack_prompt,
                "target_response": target_response
            }

def main():
    DATA_PATH = PROJECT_ROOT / "data" / "benchmark_result.json" # 실제 경로로 수정 필요
    
    # 모델 및 어댑터 설정
    BASE_MODEL_ID = "Qwen/Qwen3.5-0.8B"
    ADAPTER_PATH = str(PROJECT_ROOT / "adapters" / "lora-judge" / "checkpoint-70")

    print("[1] 토크나이저 및 모델 로딩 중...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, trust_remote_code=True)
        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            device_map="auto",
            torch_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        )
        model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
        model.eval()
    except Exception as e:
        print(f"[오류] 모델 로드 실패: {e}")
        sys.exit(1)

    print(f"\n[2] 데이터 로드 및 Chat-Template 추론 시작: {DATA_PATH}\n")
    
    try:
        for idx, data in enumerate(load_test_data(DATA_PATH), start=1):
            category = data["category"]
            attack_prompt = data["attack_prompt"]
            target_response = data["target_response"]

            # User 프롬프트 구성
            user_prompt = f"[Attack Prompt]\n{attack_prompt}\n\n[Target Response]\n{target_response}"

            # Chat-Template 규격에 맞춘 메시지 리스트 구성
            messages = build_judge_messages(
                        category=category,
                        attack_prompt=attack_prompt,
                        response=target_response
                    )

            # 토크나이저를 이용한 챗 템플릿 적용 (학습 시 데이터 형태와 100% 일치시킴)
            formatted_text = tokenizer.apply_chat_template(
                messages, 
                tokenize=False, 
                add_generation_prompt=True
            )
            
            inputs = tokenizer(formatted_text, return_tensors="pt").to(model.device)

            with torch.no_grad():
                outputs = model.generate(
                    **inputs, 
                    max_new_tokens=128,
                    temperature=0.0,
                    do_sample=False,
                    pad_token_id=tokenizer.eos_token_id
                )
            
            # 새로 생성된 토큰만 추출 (프롬프트 부분 제외)
            input_length = inputs.input_ids.shape[1]
            generated_text = tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True).strip()

            print(f"========== [Test Case {idx}] ==========")
            print(f"🔹 Chat-Template 변환 결과 (User 일부): {user_prompt[:80]}...")
            print(f"🔸 모델 판정 결과 (Raw JSON): \n{generated_text}\n")
            
            # 테스트 속도를 위해 3개만 돌리고 멈춤 (필요시 삭제)
            if idx >= 5:
                print("테스트 샘플 3개 완료. 종료합니다.")
                break

    except (FileNotFoundError, ValueError) as e:
        print(e)

if __name__ == "__main__":
    main()