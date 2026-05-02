"""
[R4] 파인튜닝 — QLoRA 학습 및 GGUF 변환 코드 (공용)
"""

import os
import sys
import torch
import argparse
import subprocess
import shutil
import json # 추가: 데이터 샘플 출력을 위함
from transformers import (
    AutoModelForCausalLM, 
    AutoTokenizer, 
    BitsAndBytesConfig, 
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    PeftModel
)
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset
from backend.config import settings
from dotenv import load_dotenv
import math
from pathlib import Path
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

load_dotenv()

# 상수: llama.cpp 저장소 경로 (환경 변수 또는 기본 경로 사용)
LLAMA_CPP_DIR = os.getenv("LLAMA_CPP_DIR", os.path.join(os.getcwd(), "llama.cpp"))

def detect_device():
    if torch.cuda.is_available():
        return "cuda"
    elif torch.backends.mps.is_available():
        return "mps"
    return "cpu"

def get_optimal_dtype_config():
    """하드웨어 아키텍처를 감지하여 최적의 Mixed Precision 설정을 반환합니다."""
    if torch.cuda.is_available() and torch.cuda.is_bf16_supported():
        return torch.bfloat16, {"bf16": True, "fp16": False}
    return torch.float16, {"bf16": False, "fp16": True}

def convert_to_gguf(merged_model_dir: str, output_gguf_path: str):
    """llama.cpp를 사용하여 HuggingFace 모델을 GGUF 포맷으로 변환합니다."""
    print("\n" + "="*50)
    print("GGUF 변환 파이프라인 가동")
    print(f" - 입력 폴더: {merged_model_dir}")
    print(f" - 출력 파일: {output_gguf_path}")
    print("="*50)

    convert_script = os.path.join(LLAMA_CPP_DIR, "convert_hf_to_gguf.py")
    
    if not os.path.exists(convert_script):
        print(f"\n[오류] llama.cpp 경로를 찾을 수 없습니다: {convert_script}")
        print("명령어 예시: git clone https://github.com/ggerganov/llama.cpp.git")
        return False

    try:
        cmd = [
            sys.executable, convert_script,
            merged_model_dir,
            "--outfile", output_gguf_path,
            "--outtype", "f16"
        ]
        
        print("변환 스크립트 실행 중... (시간이 소요될 수 있습니다)")
        subprocess.run(cmd, check=True)
        print(f"GGUF 변환 완료: {output_gguf_path}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\n[오류] GGUF 변환 중 시스템 명령 실패: {e}")
        return False

def train_role_adapter(role: str, train_file: str, output_dir: str):
    is_cuda = torch.cuda.is_available()
    compute_dtype, amp_kwargs = get_optimal_dtype_config()
    
    print(f"\n" + "="*50)
    print(f"[{role.upper()}] 파인튜닝 파이프라인 시작")
    print(f" - 데이터 경로: {train_file}")
    print(f" - Dtype: {compute_dtype} | BF16: {amp_kwargs['bf16']} | FP16: {amp_kwargs['fp16']}")
    print("="*50 + "\n")

    # 변수명 통일
    if role == "red":
        hf_model_id = os.getenv("OLLAMA_RED_LOCAL_MODEL", "Qwen/Qwen3.5-0.8B")
    elif role == "blue":
        hf_model_id = os.getenv("OLLAMA_BLUE_LOCAL_MODEL", "Qwen/Qwen3.5-0.8B")
    else:
        hf_model_id = os.getenv("OLLAMA_JUDGE_LOCAL_MODEL", "Qwen/Qwen3.5-0.8B")
        
    print(f"1. 데이터 로드 및 검증 중...")
    try:
        dataset = load_dataset("json", data_files=train_file, split="train")
        print(f" -> 성공적으로 총 {len(dataset)}개의 학습 샘플을 로드했습니다.")
        
        # [최적화] 데이터 1건을 터미널에 출력하여 구조 확인
        print("\n--- [데이터 샘플 확인 (첫 번째 데이터)] ---")
        sample_messages = dataset[0].get("messages", [])
        for msg in sample_messages:
            role_name = msg.get("role", "unknown")
            # 내용이 길 수 있으므로 150자까지만 자름
            content_preview = str(msg.get("content", ""))[:150].replace('\n', ' ')
            print(f"[{role_name.upper()}]: {content_preview}...")
        print("-------------------------------------------\n")

    except Exception as e:
        print(f"[오류] 데이터 로드 실패: {e}")
        sys.exit(1)

    print(f"2. 모델({hf_model_id}) 다운로드 및 로드 중...")
    if is_cuda:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute_dtype,
        )
        model = AutoModelForCausalLM.from_pretrained(
            hf_model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            hf_model_id,
            torch_dtype=compute_dtype,
            device_map="cpu"
        )

    if compute_dtype == torch.float16:
        for _, param in model.named_parameters():
            if param.dtype == torch.bfloat16:
                param.data = param.data.to(torch.float16)

    # [최적화 적용] Qwen 모델을 위한 명시적 Chat Template 및 패딩 처리
    tokenizer = AutoTokenizer.from_pretrained(hf_model_id, trust_remote_code=True)
    
    # Qwen 베이스 모델이 종료 토큰을 명시하지 않을 경우를 대비하여 수동으로 할당합니다.
    if tokenizer.eos_token is None:
        tokenizer.eos_token = "<|endoftext|>"
    
    # Qwen 모델의 기본 Chat Template이 적용되도록 보장
    if not hasattr(tokenizer, 'chat_template') or tokenizer.chat_template is None:
        print("[경고] 모델에 기본 Chat Template이 없습니다. Qwen 템플릿을 명시적으로 주입합니다.")
        # Qwen 모델의 일반적인 템플릿 구조 (버전에 따라 약간 다를 수 있음)
        tokenizer.chat_template = "{% for message in messages %}{{'<|im_start|>' + message['role'] + '\n' + message['content'] + '<|im_end|>' + '\n'}}{% endfor %}{% if add_generation_prompt %}{{ '<|im_start|>assistant\n' }}{% endif %}"

    # Qwen 특화 패딩 토큰 설정 (eos_token 대신 eod_id/eos_token 사용)
    if tokenizer.pad_token_id is None:
        if hasattr(tokenizer, 'eod_id'):
            tokenizer.pad_token_id = tokenizer.eod_id
            tokenizer.pad_token = tokenizer.decode(tokenizer.eod_id)
        else:
            tokenizer.pad_token_id = tokenizer.eos_token_id
            tokenizer.pad_token = tokenizer.eos_token
    
    tokenizer.padding_side = "right"
    
    lora_config = LoraConfig(
        r=16, 
        lora_alpha=32, 
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        task_type="CAUSAL_LM",
        bias="none"
    )

    # judge 역할만 기존 LoRA 체크
    judge_adapter_dir = os.path.join(PROJECT_ROOT, "adapters", "lora-judge", "checkpoint-270")
    print(f"[DEBUG] judge_adapter_dir={judge_adapter_dir}, exists={os.path.exists(judge_adapter_dir)}")

    if is_cuda:
        model = prepare_model_for_kbit_training(model)

    # safetensors만 체크
    adapter_file_safetensors = os.path.join(judge_adapter_dir, "adapter_model.safetensors")
    adapter_config_file = os.path.join(judge_adapter_dir, "adapter_config.json")

    adapter_exists = (
        os.path.exists(judge_adapter_dir)
        and os.path.exists(adapter_file_safetensors)
        and os.path.exists(adapter_config_file)
    )

    print(f"[DEBUG] adapter_exists={adapter_exists}")
    print(f"[DEBUG] safetensors={os.path.exists(adapter_file_safetensors)}")
    print(f"[DEBUG] adapter_config={os.path.exists(adapter_config_file)}")

    if role == "judge" and adapter_exists:
        print("[INFO] 기존 judge LoRA(safetensors) 가중치를 로드해서 이어서 학습합니다.")
        model = PeftModel.from_pretrained(
            model,
            judge_adapter_dir,
            is_trainable=True
        )
    else:
        print("[INFO] 새 LoRA를 생성해서 학습합니다.")
        model = get_peft_model(model, lora_config)

    if compute_dtype == torch.float16:
        for _, param in model.named_parameters():
            if param.dtype == torch.bfloat16:
                param.data = param.data.to(torch.float16)
                
    # [최적화] 훈련 가능 파라미터 수 확인 로직 추가
    model.print_trainable_parameters()
    model.enable_input_require_grads()
    
    dataset_size = len(dataset)

    per_device_batch = 4 if is_cuda else 2
    grad_accum = 4 if is_cuda else 8
    num_epochs = 50  # 너가 설정한 값

    steps_per_epoch = math.ceil(dataset_size / (per_device_batch * grad_accum))
    total_steps = steps_per_epoch * num_epochs

    print(f"[DEBUG] steps_per_epoch={steps_per_epoch}")
    print(f"[DEBUG] total_steps={total_steps}")

    print(f"\n3. SFT 학습 시작...")
    training_args = SFTConfig(
        output_dir=output_dir,

        # ✔ batch는 유지 (이미 잘 잡음)
        per_device_train_batch_size=per_device_batch,
        gradient_accumulation_steps=grad_accum,

        # 이어 학습 핵심
        num_train_epochs=num_epochs,                 # 10 → 2 (필수)
        learning_rate=1e-4,                # 2e-4 → 5e-5

        # LR 안정화
        lr_scheduler_type="cosine",
        warmup_steps =int(total_steps * 0.05),                 # steps 대신 ratio 추천

        # 과적합/폭주 방지
        max_grad_norm=0.3,
        weight_decay=0.01,

        # mixed precision
        bf16=amp_kwargs["bf16"],
        fp16=amp_kwargs["fp16"],

        # 옵티마이저
        optim="paged_adamw_32bit" if is_cuda else "adamw_torch",

        # 로그
        logging_steps=5,

        # 메모리 안정
        gradient_checkpointing=True,

        # 길이 제한
        max_length=1024,

        dataset_text_field="messages",
        packing=False,

        # 중간 저장
        save_strategy="steps",
        save_steps=27,
        save_total_limit=2,

        report_to="none"
    )

    trainer = SFTTrainer(
        model=model, 
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer
    )

    trainer.train()

    # 4. 임시 어댑터 저장
    temp_adapter_dir = os.path.join(output_dir, "temp_adapter")
    trainer.save_model(temp_adapter_dir)
    tokenizer.save_pretrained(temp_adapter_dir)
    print(f"\n[{role.upper()}] LoRA 어댑터 임시 저장 완료.")

    # 5. CPU에서 베이스 모델 로드 후 어댑터 병합
    print("\n5. 베이스 모델과 어댑터 병합(Merge)을 시작합니다...")
    base_model = AutoModelForCausalLM.from_pretrained(
        hf_model_id, 
        torch_dtype=compute_dtype, 
        device_map="cpu"
    )
    merged_model = PeftModel.from_pretrained(base_model, temp_adapter_dir)
    merged_model = merged_model.merge_and_unload()
    
    merged_model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    shutil.rmtree(temp_adapter_dir, ignore_errors=True)
    print(" -> 모델 병합 완료.")

    # 6. GGUF 포맷으로 변환
    gguf_filename = f"{role}_model_f16.gguf"
    gguf_path = os.path.join(output_dir, gguf_filename)
    
    success = convert_to_gguf(output_dir, gguf_path)

    # 7. Ollama Modelfile 생성 및 등록 가이드
    if success:
        modelfile_path = os.path.join(output_dir, "Modelfile")
        modelfile_content = f"FROM ./{gguf_filename}\n"
        
        with open(modelfile_path, "w", encoding="utf-8") as f:
            f.write(modelfile_content)
            
        agent_name = f"agent-{role}"
        print("\n" + "=" * 50)
        print(f"[Ollama 연동 가이드 - GGUF 기반]")
        print(f"변환된 단일 GGUF 파일로 시스템 환경에 구애받지 않고 배포가 가능합니다.")
        print(f"터미널에서 아래 폴더로 이동 후 모델을 생성하세요:")
        print(f"  cd {os.path.abspath(output_dir)}")
        print(f"  ollama create {agent_name} -f Modelfile")
        print("=" * 50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Role-based LoRA Fine-tuning and GGUF Conversion")
    parser.add_argument("--role", choices=["red", "judge", "blue"], required=True, help="에이전트 역할")
    parser.add_argument("--data", required=True, help="학습용 JSONL 데이터 경로")
    parser.add_argument("--output", default=None, help="최종 저장 경로")
    args = parser.parse_args()

    if args.output:
        final_output = args.output
    else:
        path_map = {
            "red": settings.LORA_RED_PATH,
            "judge": settings.LORA_JUDGE_PATH,
            "blue": settings.LORA_BLUE_PATH,
        }
        final_output = path_map[args.role]

    print(f"최종 출력 경로: '{final_output}'")
    os.makedirs(final_output, exist_ok=True)
    train_role_adapter(args.role, args.data, final_output)