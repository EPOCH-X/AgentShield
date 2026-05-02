import os
import sys
import torch
import argparse
import subprocess
import shutil
import json
import math
import re

from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainerCallback
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    PeftModel
)
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

LLAMA_CPP_DIR = os.getenv("LLAMA_CPP_DIR", os.path.join(os.getcwd(), "llama.cpp"))


# =========================
# JSON 평가 로직
# =========================

# def extract_json(text):
#     match = re.search(r"\{.*\}", text, re.DOTALL)
#     if not match:
#         return None
#     try:
#         return json.loads(match.group(0))
#     except:
#         return None


# @torch.no_grad()
# def compute_json_success_rate(model, tokenizer, dataset, max_samples=30):
#     model.eval()

#     success = 0
#     total = 0

#     for i, sample in enumerate(dataset):
#         if i >= max_samples:
#             break

#         messages = sample["messages"][:-1]

#         prompt = tokenizer.apply_chat_template(
#             messages,
#             tokenize=False,
#             add_generation_prompt=True
#         )

#         inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

#         outputs = model.generate(
#             **inputs,
#             max_new_tokens=256,
#             do_sample=False,
#             temperature=0.0,
#             top_p=1.0,
#         )

#         input_len = inputs["input_ids"].shape[-1]
#         generated_ids = outputs[0][input_len:]
#         decoded = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()

#         if i == 0:
#             with open("debug.txt", "w", encoding="utf-8") as f:
#                 f.write(decoded[:1000])

#         obj = extract_json(decoded)

#         if obj and all(k in obj for k in ["judgment", "score", "reason"]):
#             success += 1

#         total += 1

#     return success / total if total > 0 else 0


# class JsonEvalCallback(TrainerCallback):
#     def __init__(self, eval_dataset, tokenizer):
#         self.eval_dataset = eval_dataset
#         self.tokenizer = tokenizer

#     def on_evaluate(self, args, state, control, model=None, **kwargs):
#         rate = compute_json_success_rate(model, self.tokenizer, self.eval_dataset)
#         print(f"\nJSON success rate: {rate:.2%}\n")


# =========================
# 학습 함수
# =========================

def train_role_adapter(role, train_file, output_dir):
    is_cuda = torch.cuda.is_available()

    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16

    print(f"\n[{role.upper()}] TRAIN START")

    hf_model_id = "Qwen/Qwen3.5-0.8B"

    # -------------------------
    # 데이터 로드
    # -------------------------
    dataset = load_dataset("json", data_files=train_file, split="train")

    tokenizer = AutoTokenizer.from_pretrained(hf_model_id, trust_remote_code=True)

    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    # messages → text 변환
    def to_text(example):
        example["text"] = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False
        )
        return example

    dataset = dataset.map(to_text)
    print(dataset[0].keys())

    eval_dataset = dataset.select(range(min(50, len(dataset))))

    # -------------------------
    # 모델 로드
    # -------------------------
    if is_cuda:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=compute_dtype
        )
        model = AutoModelForCausalLM.from_pretrained(
            hf_model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            hf_model_id,
            torch_dtype=compute_dtype
        )

    if is_cuda:
        model = prepare_model_for_kbit_training(model)

    # -------------------------
    # LoRA 이어학습
    # -------------------------
    judge_adapter_dir = os.path.join(
        PROJECT_ROOT,
        "adapters",
        "lora-judge",
        "checkpoint-270"
    )

    adapter_exists = (
        os.path.exists(os.path.join(judge_adapter_dir, "adapter_model.safetensors"))
        and os.path.exists(os.path.join(judge_adapter_dir, "adapter_config.json"))
    )

    if role == "judge" and adapter_exists:
        print("기존 LoRA 이어 학습")
        model = PeftModel.from_pretrained(
            model,
            judge_adapter_dir,
            is_trainable=True
        )
    else:
        print("새 LoRA 생성")
        lora_config = LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)

    model.print_trainable_parameters()

    # -------------------------
    # STEP 계산
    # -------------------------
    dataset_size = len(dataset)
    batch = 4 if is_cuda else 2
    grad_accum = 4 if is_cuda else 8
    epochs = 3

    steps_per_epoch = math.ceil(dataset_size / (batch * grad_accum))
    total_steps = steps_per_epoch * epochs

    print(f"[DEBUG] total_steps={total_steps}")

    # -------------------------
    # 학습 설정
    # -------------------------
    training_args = SFTConfig(
        output_dir=output_dir,
        per_device_train_batch_size=batch,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=epochs,
        learning_rate=1e-4,
        lr_scheduler_type="cosine",
        warmup_steps=int(total_steps * 0.05),
        max_grad_norm=0.3,
        weight_decay=0.01,
        bf16=torch.cuda.is_bf16_supported(),
        fp16=not torch.cuda.is_bf16_supported(),
        logging_steps=10,
        save_strategy="steps",
        save_steps=steps_per_epoch,
        eval_strategy="steps",
        eval_steps=steps_per_epoch,
        dataset_text_field="text",
        max_length=1024,
        report_to="none"
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer
    )

    trainer.train()

    # -------------------------
    # 저장
    # -------------------------
    temp_dir = os.path.join(output_dir, "temp_adapter")
    trainer.save_model(temp_dir)
    tokenizer.save_pretrained(temp_dir)

    base_model = AutoModelForCausalLM.from_pretrained(
        hf_model_id,
        torch_dtype=compute_dtype,
        device_map="cpu"
    )

    merged = PeftModel.from_pretrained(base_model, temp_dir)
    merged = merged.merge_and_unload()

    merged.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    shutil.rmtree(temp_dir, ignore_errors=True)

    print("\nTRAIN COMPLETE")


# =========================
# ENTRY
# =========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    train_role_adapter(args.role, args.data, args.output)