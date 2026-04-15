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
from trl import SFTTrainer
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
    model_id = "google/gemma-4-E2B"

    # 기반 모델 로드 — CUDA는 QLoRA 4-bit, MPS/CPU는 float16 전체 로드
    if use_quantization:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            device_map="auto" if device_type == "cpu" else None
        )
        if device_type == "mps":
            model = model.to("mps")

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

    if use_quantization:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 데이터셋 로드
    dataset = load_dataset("json", data_files=train_file)

    def formatting_prompts_func(example):
        output_texts = []
        for i in range(len(example['instruction'])):
            # Gemma 전용 프롬프트 템플릿 적용 (2026년 기준 표준 가안)
            text = f"<start_of_turn>user\n{example['instruction'][i]}\n{example['input'][i]}<end_of_turn>\n"
            text += f"<start_of_turn>model\n{example['output'][i]}<end_of_turn>"
            output_texts.append(text)
        return output_texts

    # 학습 설정 — 디바이스별 분기
    if device_type == "cuda":
        training_args = TrainingArguments(
            output_dir=output_dir,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            num_train_epochs=3,
            learning_rate=2e-4,
            lr_scheduler_type="cosine",
            warmup_ratio=0.03,
            fp16=True,
            optim="paged_adamw_32bit",
            save_strategy="epoch",
            logging_steps=10,
            max_grad_norm=0.3,
            gradient_checkpointing=True
        )
    else:
        # MPS / CPU — fp16 OFF, 표준 optimizer, 배치 축소
        training_args = TrainingArguments(
            output_dir=output_dir,
            per_device_train_batch_size=2,
            gradient_accumulation_steps=8,
            num_train_epochs=3,
            learning_rate=2e-4,
            lr_scheduler_type="cosine",
            warmup_ratio=0.03,
            fp16=False,
            optim="adamw_torch",
            save_strategy="epoch",
            logging_steps=10,
            max_grad_norm=0.3,
            gradient_checkpointing=True,
            use_mps_device=(device_type == "mps")
        )

    # SFTTrainer로 학습
    trainer = SFTTrainer(
        model=model, 
        args=training_args,
        train_dataset=dataset["train"],
        dataset_text_field="text",   # JSONL 파일 내에서 학습할 텍스트가 있는 키 값 지정 필수
        formatting_func=formatting_prompts_func,
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
    adapter_file = "adapter_model.safetensors" if os.path.exists(os.path.join(output_dir, "adapter_model.safetensors")) else "adapter_model.bin"
    absolute_adapter_path = os.path.abspath(os.path.join(output_dir, adapter_file))

    modelfile_content = f"FROM {settings.OLLAMA_MODEL}\nADAPTER {absolute_adapter_path}"

    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    agent_name = f"agent-{role}"
    print("=" * 50)
    print(f"\n[Ollama {agent_name} 자동 저장 시작]\n")
    try:
        # subprocess.run을 사용해 터미널 명령어를 직접 실행합니다.
        result = subprocess.run(
            ["ollama", "create", agent_name, "-f", modelfile_path],
            capture_output=True, # 실행 결과를 변수에 담음
            text=True,           # 출력을 문자열로 처리
            check=True           # 명령어 실패 시 예외 발생
        )
        print(f"[Ollama] 등록 성공: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"[Ollama] 등록 실패: {e.stderr}")
    except FileNotFoundError:
        print("[Ollama] 시스템에서 'ollama' 명령어를 찾을 수 없습니다. Ollama가 설치되어 있나요?")
        
    print(f"\n[완료 {role.upper()}] 아래의 수동버전은 실행할 필요 없습니다.\n")

    print("=" * 50)
    print(f"\n[Ollama 연동 가이드 - 수동]\n")
    print(f"다음 명령어를 터미널에 입력하여 '{role}' 에이전트를 Ollama에 등록하세요:")
    print(f"ollama create agent-{role} -f {modelfile_path}\n")
  
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