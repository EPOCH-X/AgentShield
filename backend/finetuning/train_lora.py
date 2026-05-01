"""
[R4] 파인튜닝 — QLoRA 학습 코드 (공용)

기능별 파이프라인 섹션 8 참조.
사용법: python train_lora.py --role red --data data/finetuning/red_train.jsonl --output adapters/lora-red

학습 설정:
  기반 모델: Gemma 4 E2B
  양자화: QLoRA (4-bit NF4)
  LoRA: r=16, lora_alpha=32, target_modules=[q/v/k/o_proj]
  학습: batch=4, grad_accum=4, epochs=3, lr=2e-4, max_seq=2048
"""

# TODO: [R4] 구현
# - train_role_adapter(role, train_file, output_dir)
# - argparse CLI

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import torch
import argparse
import subprocess
from transformers import (
    AutoModelForCausalLM, 
    AutoTokenizer, 
    BitsAndBytesConfig, 
    TrainingArguments
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training
)
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

from backend.config import settings


def detect_device():
    """
    학습 환경 자동 감지.
    CUDA(NVIDIA GPU) > MPS(Apple Silicon) > CPU 순으로 우선 선택.
    """
    if torch.cuda.is_available():
        return "cuda"
    elif torch.backends.mps.is_available():
        return "mps"
    else:
        return "cpu"


def train_role_adapter(role: str, train_file: str, output_dir: str):
    """
    역할별 LoRA 어댑터 학습 및 Ollama 연동 자동화.
    CUDA / MPS / CPU 환경을 자동 감지하여 설정을 분기한다.
    """
    device_type = detect_device()
    use_quantization = (device_type == "cuda")  # QLoRA(bitsandbytes)는 CUDA 전용

    print(f"\n" + "="*50)
    print(f"[{role.upper()}] 파인튜닝 시작")
    print(f" - 데이터: {train_file}")
    print(f" - 출력 경로: {output_dir}")
    print(f" - 감지된 디바이스: {device_type}")
    print(f" - QLoRA 4-bit 양자화: {'ON' if use_quantization else 'OFF (bitsandbytes는 CUDA 전용)'}")
    print("="*50 + "\n")

    # 모델 id 설정
    model_id = "Qwen/Qwen3.5-0.8B"

    # 기반 모델 로드 — CUDA는 QLoRA 4-bit, MPS/CPU는 float16 전체 로드
    if use_quantization:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,   # 추가
            quantization_config=bnb_config,
            device_map="auto",
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,   # CPU/MPS도 일단 float16 통일
            device_map="auto" if device_type == "cpu" else None,
        )

    # 토그나이저
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.default_bos_token
    tokenizer.padding_side = "right"

    # LoRA 설정
    lora_config = LoraConfig(
        r=16, 
        lora_alpha=32, 
        lora_dropout=0.1,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        task_type="CAUSAL_LM",
        bias="none"
    )

    if use_quantization:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 데이터셋 로드
    dataset = load_dataset("json", data_files=train_file)

    # 학습 설정 — 디바이스별 분기
    is_cuda = (device_type == "cuda")
    is_cpu = (device_type == "cpu")

    batch_size = 4 if is_cuda else 2
    grad_accum = 4 if is_cuda else 8
    use_fp16 = True if is_cuda else False
    optimizer = "paged_adamw_32bit" if is_cuda else "adamw_torch"

    sft_config = SFTConfig(
        output_dir=output_dir,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=1,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_steps=20,
        fp16=use_fp16,
        bf16=False,   # 확실히 끄기
        use_cpu=is_cpu,
        optim=optimizer,
        save_strategy="epoch",
        logging_steps=1,
        max_grad_norm=0.3,
        gradient_checkpointing=True,
        max_length=2048,
        packing=False,
    )

    # SFTTrainer로 학습
    trainer = SFTTrainer(
        model=model, 
        args=sft_config,
        train_dataset=dataset["train"],
        processing_class=tokenizer
    )
    trainer.train()

    # 모델과 토크나이저를 함께 저장
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"[{role.upper()}] 어댑터 저장 완료: {output_dir}")

    # Ollama 자동 연동을 위한 Modelfile 생성
    modelfile_path = os.path.join(output_dir, "Modelfile")
    adapter_file = "adapter_model.safetensors" if os.path.exists(os.path.join(output_dir, "adapter_model.safetensors")) else "adapter_model.bin"
    absolute_adapter_path = os.path.abspath(os.path.join(output_dir, adapter_file))

    modelfile_content = f"FROM {settings.OLLAMA_MODEL}\nADAPTER {absolute_adapter_path}"

    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    agent_name = f"agent-{role}"
    print("=" * 50)
    print(f"\n[Ollama 연동 가이드 - 수동]\n")
    print(f"다음 명령어를 터미널에 입력하여 '{role}' 에이전트를 Ollama에 등록하세요:")
    print(f"ollama create {agent_name} -f {modelfile_path}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Role-based LoRA Fine-tuning")
    parser.add_argument("--role", choices=["red", "judge", "blue"], required=True, help="에이전트 역할")
    parser.add_argument("--data", required=True, help="학습용 JSONL 데이터 경로")
    parser.add_argument("--output", default=None, help="어댑터 저장 경로 (입력하지 않으면 settings 기본 경로 사용)")
    args = parser.parse_args()
    
    # 출력 경로 결정 (settings 기본값)
    if args.output:
        final_output = args.output
    else:
        path_map = {
            "red": settings.LORA_RED_PATH,
            "judge": settings.LORA_JUDGE_PATH,
            "blue": settings.LORA_BLUE_PATH
        }
        final_output = path_map[args.role]

    print(f"최종 저장 경로가 '{final_output}'(으)로 설정되었습니다.")

    os.makedirs(final_output, exist_ok=True)
    train_role_adapter(args.role, args.data, final_output)