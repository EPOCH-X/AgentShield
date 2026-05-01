"""
[R4] 파인튜닝 — QLoRA 학습 코드 (공용)
"""

import os

# CUDA 메모리 fragmentation 완화
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
os.environ.setdefault("ACCELERATE_MIXED_PRECISION", "fp16")

import sys
import argparse
from pathlib import Path

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

from backend.config import settings


def detect_device():
    if torch.cuda.is_available():
        return "cuda"
    elif torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def train_role_adapter(role: str, train_file: str, output_dir: str):
    device_type = detect_device()
    use_quantization = (device_type == "cuda")

    print(f"\n{'='*50}")
    print(f"[{role.upper()}] 파인튜닝 시작")
    print(f" - 데이터: {train_file}")
    print(f" - 출력 경로: {output_dir}")
    print(f" - 감지된 디바이스: {device_type}")
    print(f" - QLoRA 4-bit 양자화: {'ON' if use_quantization else 'OFF'}")
    print(f"{'='*50}\n")

    model_id = "Qwen/Qwen3.5-0.8B"

    # 1) 모델 로드
    if use_quantization:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            dtype=torch.float16,
            quantization_config=bnb_config,
            device_map="auto",
        )
    else:
        load_dtype = torch.float32 if device_type == "cpu" else torch.float16
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            dtype=load_dtype,
            device_map="auto" if device_type != "cuda" else None,
        )

    # 2) 메모리 절약용 필수 옵션
    model.config.use_cache = False
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()

    # 3) 토크나이저
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # 4) LoRA: 메모리 줄이기 위해 target modules 축소
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj"],
        task_type="CAUSAL_LM",
        bias="none",
    )

    if use_quantization:
        model = prepare_model_for_kbit_training(model)

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 5) 데이터셋
    dataset = load_dataset("json", data_files=train_file)

    # 6) 아주 보수적인 학습 설정
    sft_config = SFTConfig(
        output_dir=output_dir,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=16,
        num_train_epochs=1,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_steps=20,
        fp16=True,
        bf16=False,
        tf32=False,
        use_cpu=(device_type == "cpu"),
        optim="paged_adamw_32bit" if device_type == "cuda" else "adamw_torch",
        save_strategy="epoch",
        logging_steps=1,
        max_grad_norm=0.3,
        gradient_checkpointing=True,
        max_length=512,
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=dataset["train"],
        processing_class=tokenizer,
    )

    trainer.train()

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"[{role.upper()}] 어댑터 저장 완료: {output_dir}")

    modelfile_path = os.path.join(output_dir, "Modelfile")
    adapter_file = (
        "adapter_model.safetensors"
        if os.path.exists(os.path.join(output_dir, "adapter_model.safetensors"))
        else "adapter_model.bin"
    )
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
    parser.add_argument("--output", default=None, help="어댑터 저장 경로")
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

    print(f"최종 저장 경로가 '{final_output}'(으)로 설정되었습니다.")
    os.makedirs(final_output, exist_ok=True)
    train_role_adapter(args.role, args.data, final_output)