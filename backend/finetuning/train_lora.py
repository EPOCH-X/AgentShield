"""
[R4] Red Agent QLoRA SFT — Qwen3.5-2B Abliterated
TRL 1.3.0 기준: SFTConfig + SFTTrainer(peft_config=) API 사용

사용법:
  python backend/finetuning/train_lora.py \
    --role red \
    --data data/finetuning/red_train_qwen35_2b_4096_compressed.jsonl \
    --output adapters/lora-red-qwen35-2b-abliterated

환경변수:
  RED_SFT_BASE_MODEL   로컬 경로 또는 HF 모델 ID
                       (기본: /Users/parkyeonggon/.cache/huggingface/qwen3.5-2b-abliterated)
  LORA_RED_PATH        --output 미지정 시 저장 경로

데이터 포맷:
  {"text": "<|im_start|>system\\n...<|im_end|>\\n<|im_start|>user\\n...<|im_end|>\\n<|im_start|>assistant\\n...<|im_end|>\\n"}
  → scripts/prepare_red_sft_data.py --model <경로> 로 생성
"""

import os
import time
import torch
import argparse
import subprocess
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainerCallback, TrainerState, TrainerControl
from peft import LoraConfig
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset


_RED_MODEL_ID = os.getenv(
    "RED_SFT_BASE_MODEL",
    "/Users/parkyeonggon/.cache/huggingface/qwen3.5-2b-abliterated",
)

# Qwen 계열 표준 LoRA 타겟 (Qwen2/3 공통, wrapper 없이 직접 nn.Linear)
_QWEN_LORA_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
]

_CHATML_MARKERS = ("<|im_start|>", "<|im_end|>")


class _ProgressCallback(TrainerCallback):

    def __init__(self):
        self._t0 = time.time()
        self._last_loss: float | None = None

    def on_train_begin(self, args, state: TrainerState, control: TrainerControl, **_):
        print(f"\n{'─'*55}")
        print(f"  학습 시작 | 총 {state.max_steps} steps | {args.num_train_epochs} epochs")
        print(f"  배치={args.per_device_train_batch_size} | grad_accum={args.gradient_accumulation_steps} | lr={args.learning_rate}")
        print(f"{'─'*55}")
        return control

    def on_log(self, args, state: TrainerState, control: TrainerControl, logs=None, **_):
        loss = (logs or {}).get("loss")
        if loss is None:
            return control
        elapsed = time.time() - self._t0
        step = state.global_step
        total = state.max_steps or 1
        pct = step / total * 100
        eta_s = elapsed / step * (total - step) if step > 0 else 0
        eta = f"{int(eta_s // 60)}m{int(eta_s % 60)}s"
        lr = logs.get("learning_rate", 0)
        gn = logs.get("grad_norm", 0)
        epoch = logs.get("epoch", 0)
        trend = ""
        if self._last_loss is not None:
            trend = "↓" if loss < self._last_loss else ("↑" if loss > self._last_loss else "→")
        self._last_loss = loss
        print(
            f"  [{pct:5.1f}%] step={step}/{total} | epoch={epoch:.2f} | "
            f"loss={loss:.4f}{trend} | grad={gn:.3f} | lr={lr:.2e} | ETA={eta}"
        )
        return control

    def on_epoch_end(self, _args, state: TrainerState, control: TrainerControl, **_kw):
        elapsed = time.time() - self._t0
        loss_str = f"{self._last_loss:.4f}" if self._last_loss else "?"
        print(f"\n  ✓ Epoch {int(round(state.epoch or 0))} 완료 | loss={loss_str} | 경과={int(elapsed // 60)}m{int(elapsed % 60)}s\n")
        return control

    def on_train_end(self, _args, _state: TrainerState, control: TrainerControl, **_kw):
        elapsed = time.time() - self._t0
        print(f"\n{'─'*55}")
        if self._last_loss:
            print(f"  학습 완료 | 총 {int(elapsed // 60)}m{int(elapsed % 60)}s | 최종 loss={self._last_loss:.4f}")
        else:
            print("  학습 완료")
        print(f"{'─'*55}\n")
        return control


def detect_device() -> str:
    if torch.cuda.is_available():
        return "cuda"
    elif torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def _verify_data_format(train_file: str) -> None:
    with open(train_file, encoding="utf-8") as f:
        first_line = f.readline()
    if not any(m in first_line for m in _CHATML_MARKERS):
        raise ValueError(
            f"\n[데이터 포맷 오류] {train_file} 이 ChatML(<|im_start|>) 포맷이 아닙니다.\n"
            "먼저 실행하세요:\n"
            "  python scripts/prepare_red_sft_data.py "
            f"--model {_RED_MODEL_ID} --output <출력경로>"
        )


def train_role_adapter(role: str, train_file: str, output_dir: str) -> None:
    device_type = detect_device()
    use_quantization = device_type == "cuda"

    print(f"\n{'='*55}")
    print(f"[{role.upper()}] Red Agent SFT (Qwen3.5-2B, TRL 1.3.0)")
    print(f"  모델    : {_RED_MODEL_ID}")
    print(f"  데이터  : {train_file}")
    print(f"  출력    : {output_dir}")
    print(f"  디바이스: {device_type} | QLoRA: {'ON' if use_quantization else 'OFF'}")
    print(f"{'='*55}\n")

    _verify_data_format(train_file)

    # ── 모델 로드 ──────────────────────────────────────────────
    if use_quantization:
        from transformers import BitsAndBytesConfig
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        model = AutoModelForCausalLM.from_pretrained(
            _RED_MODEL_ID, quantization_config=bnb_config, device_map="auto",
        )
    elif device_type == "mps":
        model = AutoModelForCausalLM.from_pretrained(
            _RED_MODEL_ID, dtype=torch.float16,
        )
        model = model.to("mps")
    else:
        model = AutoModelForCausalLM.from_pretrained(
            _RED_MODEL_ID, dtype=torch.float16,
        )

    total_params = sum(p.numel() for p in model.parameters())
    print(f"  모델 파라미터: {total_params/1e9:.2f}B")

    # ── 토크나이저 ─────────────────────────────────────────────
    tokenizer = AutoTokenizer.from_pretrained(_RED_MODEL_ID)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id
    tokenizer.padding_side = "right"

    # ── LoRA 설정 ──────────────────────────────────────────────
    lora_config = LoraConfig(
        r=64,
        lora_alpha=128,
        lora_dropout=0.05,
        target_modules=_QWEN_LORA_MODULES,
        task_type="CAUSAL_LM",
        bias="none",
    )

    # ── 데이터셋 로드 ──────────────────────────────────────────
    dataset = load_dataset("json", data_files=train_file)
    print(f"  학습 샘플 수: {len(dataset['train'])}")

    # ── SFTConfig ─────────────────────────────────────────────
    sft_common = dict(
        output_dir=output_dir,
        dataset_text_field="text",
        max_length=4096,
        packing=False,
        num_train_epochs=3,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        save_strategy="epoch",
        logging_steps=5,
        max_grad_norm=0.3,
        gradient_checkpointing=True,
        report_to="none",
        remove_unused_columns=False,
    )

    if device_type == "cuda":
        sft_args = SFTConfig(
            **sft_common,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            bf16=True,
            optim="paged_adamw_32bit",
        )
    else:
        sft_args = SFTConfig(
            **sft_common,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=16,
            fp16=False,
            bf16=False,
            optim="adamw_torch",
        )

    # ── SFTTrainer ─────────────────────────────────────────────
    trainer = SFTTrainer(
        model=model,
        args=sft_args,
        train_dataset=dataset["train"],
        processing_class=tokenizer,
        peft_config=lora_config,
        callbacks=[_ProgressCallback()],
    )
    trainer.train()

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"\n[{role.upper()}] 어댑터 저장 완료: {output_dir}")

    # ── Modelfile 생성 ─────────────────────────────────────────
    modelfile_path = os.path.join(output_dir, "Modelfile")
    adapter_file = (
        "adapter_model.safetensors"
        if os.path.exists(os.path.join(output_dir, "adapter_model.safetensors"))
        else "adapter_model.bin"
    )
    abs_adapter = os.path.abspath(os.path.join(output_dir, adapter_file))
    ollama_base = os.getenv("OLLAMA_RED_MODEL", "hauhau-qwen-aggressive:latest")

    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(f"FROM {ollama_base}\nADAPTER {abs_adapter}\n")

    print(f"[Ollama] Modelfile 생성: {modelfile_path}")
    print(f"  ※ adapter 병합/변환 후 Ollama 등록 필요:")
    print(f"     ollama create agent-{role} -f {modelfile_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red Agent QLoRA SFT (Qwen3.5-2B, TRL 1.3.0)")
    parser.add_argument("--role", choices=["red", "judge", "blue"], required=True)
    parser.add_argument("--data", required=True, help="JSONL 경로 (ChatML 포맷)")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    final_output = args.output or {
        "red":   os.getenv("LORA_RED_PATH",   "./adapters/lora-red-qwen35-2b-abliterated"),
        "judge": os.getenv("LORA_JUDGE_PATH",  "./adapters/lora-judge"),
        "blue":  os.getenv("LORA_BLUE_PATH",   "./adapters/lora-blue"),
    }[args.role]

    os.makedirs(final_output, exist_ok=True)
    print(f"저장 경로: {final_output}")
    train_role_adapter(args.role, args.data, final_output)
