import os
import sys
import torch
import argparse
import shutil
import json
import math

from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig
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
# TRAIN
# =========================

def train_role_adapter(role, train_file, output_dir):
    is_cuda = torch.cuda.is_available()
    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16

    print(f"\n[{role.upper()}] TRAIN START")

    hf_model_id = "Qwen/Qwen3.5-0.8B"

    # -------------------------
    # DATA
    # -------------------------
    dataset = load_dataset("json", data_files=train_file, split="train")

    tokenizer = AutoTokenizer.from_pretrained(hf_model_id, trust_remote_code=True)

    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    # messages → text (SFT 표준)
    def to_text(example):
        example["text"] = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False
        )
        return example

    dataset = dataset.map(to_text)

    eval_dataset = dataset.select(range(min(50, len(dataset))))

    # -------------------------
    # MODEL
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
    # LoRA
    # -------------------------
    judge_adapter_dir = os.path.join(
        PROJECT_ROOT,
        "adapters",
        "lora-judge",
        "checkpoint-270"
    )

    adapter_exists = (
        os.path.exists(os.path.join(judge_adapter_dir, "adapter_model.safetensors")) and
        os.path.exists(os.path.join(judge_adapter_dir, "adapter_config.json"))
    )

    if role == "judge" and adapter_exists:
        print("LoRA 이어학습")
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
    # STEP
    # -------------------------
    dataset_size = len(dataset)
    batch = 4 if is_cuda else 2
    grad_accum = 4 if is_cuda else 8
    epochs = 5

    steps_per_epoch = math.ceil(dataset_size / (batch * grad_accum))
    total_steps = steps_per_epoch * epochs

    print(f"[DEBUG] total_steps={total_steps}")

    # -------------------------
    # TRAIN CONFIG
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
    # SAVE
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