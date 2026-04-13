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
import torch
import argparse
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
from trl import SFTTrainer
from datasets import load_dataset

def train_role_adapter(role: str, train_file: str, output_dir: str):
    """
    역할별 LoRA 어댑터 학습 및 Ollama 연동 준비.
    사용법: python train_lora.py --role red --data data/finetuning/red_train.jsonl --output adapters/lora-red
    """
    print(f"[{role.upper()}] 파인튜닝 시작 | 데이터: {train_file}")

    # 모델 id 설정
    model_id = "google/gemma-4-E2B"

    # 양자화, 4-bit
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16
    )

    # 기반 모델: Gemma 4 E2B
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map="auto"
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
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        task_type="CAUSAL_LM",
        bias="none"
    )

    model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 데이터셋 로드
    dataset = load_dataset("json", data_files=train_file)

    # 학습 설정
    training_args = TrainingArguments(
        output_dir=output_dir,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        num_train_epochs=3,
        learning_rate=2e-4,
        lr_scheduler_type="cosine", # 보폭을 코사인 곡선 모양으로 부드럽게 줄임
        warmup_ratio=0.03,          # 전체 학습량의 3% 구간 동안 천천히 보폭 상승
        fp16=True,
        optim="paged_adamw_32bit",   # QLoRA OOM 스파이크 방지용 필수 옵티마이저
        save_strategy="epoch",
        logging_steps=10,
        max_grad_norm=0.3            # 그래디언트 폭발 방지
    )

    # SFTTrainer로 학습
    trainer = SFTTrainer(
        model=model, 
        args=training_args,
        train_dataset=dataset["train"],
        dataset_text_field="text",   # JSONL 파일 내에서 학습할 텍스트가 있는 키 값 지정 필수
        tokenizer=tokenizer,
        max_seq_length=2048,
        packing=False
    )
    trainer.train()

    # 모델과 토크나이저를 함께 저장
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"[{role.upper()}] 어댑터 저장 완료: {output_dir}")

    # Ollama 자동 연동을 위한 Modelfile 생성
    modelfile_path = os.path.join(output_dir, "Modelfile")
    absolute_adapter_path = os.path.abspath(os.path.join(output_dir, "adapter_model.safetensors"))

    modelfile_content = f"FROM gemma4:e2b\nADAPTER {absolute_adapter_path}"

    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    print(f"\n[Ollama 연동 가이드]")
    print(f"다음 명령어를 터미널에 입력하여 '{role}' 에이전트를 Ollama에 등록하세요:")
    print(f"ollama create agent-{role} -f {modelfile_path}\n")
  
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Role-based LoRA Fine-tuning")
    parser.add_argument("--role", choices=["red", "judge", "blue"], required=True, help="에이전트 역할")
    parser.add_argument("--data", required=True, help="학습용 JSONL 데이터 경로")
    parser.add_argument("--output", required=True, help="어댑터 저장 경로")
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    train_role_adapter(args.role, args.data, args.output)