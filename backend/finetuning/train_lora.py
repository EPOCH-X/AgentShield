"""
[R4] 파인튜닝 — QLoRA 학습 코드 (공용)
"""

import os
import sys
import torch
import argparse
import json
from transformers import (
    AutoModelForCausalLM, 
    AutoTokenizer, 
    BitsAndBytesConfig, 
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
    if torch.cuda.is_available():
        return "cuda"
    elif torch.backends.mps.is_available():
        return "mps"
    return "cpu"

def get_optimal_dtype_config():
    """
    [최적화] 하드웨어 아키텍처를 감지하여 최적의 Mixed Precision 설정을 반환합니다.
    """
    if torch.cuda.is_available() and torch.cuda.is_bf16_supported():
        # RTX 30시리즈 이상: BFloat16 사용 (GradScaler 비활성화로 에러 원천 차단)
        return torch.bfloat16, {"bf16": True, "fp16": False}
    else:
        # RTX 20시리즈 이하: FP16 사용
        return torch.float16, {"bf16": False, "fp16": True}

def train_role_adapter(role: str, train_file: str, output_dir: str):
    is_cuda = torch.cuda.is_available()
    
    # 1. 동적 데이터 타입 및 인자 할당 (변수명 통일성 확보)
    compute_dtype, amp_kwargs = get_optimal_dtype_config()
    
    print(f"\n" + "="*50)
    print(f"[{role.upper()}] 파인튜닝 아키텍처 가동")
    print(f" - 하드웨어 지원 Dtype: {compute_dtype}")
    print(f" - AMP 설정: BF16({amp_kwargs['bf16']}), FP16({amp_kwargs['fp16']})")
    print("="*50 + "\n")

    model_id = "Qwen/Qwen3.5-0.8B"

    # 2. 모델 로드
    if is_cuda:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute_dtype,
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=compute_dtype,
            device_map="cpu"
        )

    # [핵심 방어 로직] FP16 사용 시, Qwen 모델 내부에 남아있는 BFloat16 잔재를 강제 변환
    if compute_dtype == torch.float16:
        for name, param in model.named_parameters():
            if param.dtype == torch.bfloat16:
                param.data = param.data.to(torch.float16)

    # 3. 토크나이저 설정
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # 4. LoRA 어댑터 설정
    lora_config = LoraConfig(
        r=16, 
        lora_alpha=32, 
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        task_type="CAUSAL_LM",
        bias="none"
    )

    if is_cuda:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, lora_config)

    # 다시 한 번 강제 변환 (LoRA 가중치 초기화 시점 방어)
    if compute_dtype == torch.float16:
        for name, param in model.named_parameters():
            if param.dtype == torch.bfloat16:
                param.data = param.data.to(torch.float16)

    # 5. SFT 학습 설정
    training_args = SFTConfig(
        output_dir=output_dir,
        per_device_train_batch_size=4 if is_cuda else 2,
        gradient_accumulation_steps=4 if is_cuda else 8,
        num_train_epochs=3,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_steps=20,
        bf16=amp_kwargs["bf16"], # 동적 할당
        fp16=amp_kwargs["fp16"], # 동적 할당
        optim="paged_adamw_32bit" if is_cuda else "adamw_torch",
        logging_steps=5,
        max_grad_norm=0.3,
        gradient_checkpointing=True,
        max_length=1024,
        dataset_text_field="messages",
        packing=False,
    )

    trainer = SFTTrainer(
        model=model, 
        args=training_args,
        train_dataset=load_dataset("json", data_files=train_file, split="train"),
        processing_class=tokenizer
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