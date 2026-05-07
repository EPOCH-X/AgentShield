"""
[R4] Red Agent QLoRA SFT — Qwen3.5-2B Abliterated
TRL 1.3.0 기준: SFTConfig + SFTTrainer(peft_config=) API 사용

기능별 파이프라인 섹션 8 참조.

사용 예:
  Qwen3.5 2B (기본 HF 베이스: Qwen/Qwen3.5-2B, --model-id 생략 시 동일):
    python backend/finetuning/train_lora.py --role blue --data data/finetuning/blue_train.jsonl \\
      --output adapters/lora-blue-qwen --ollama-from qwen3.5:2b

  Qwen3.5 4B 등 다른 HF 베이스:
    python backend/finetuning/train_lora.py --role blue --data data/finetuning/blue_train.jsonl \\
      --model-id Qwen/Qwen3.5-4B --output adapters/lora-blue-qwen4 --ollama-from qwen3.5:4b

  Gemma 4 E2B:
    python backend/finetuning/train_lora.py --role blue --data data/finetuning/blue_train.jsonl \\
      --model-id google/gemma-4-E2B --ollama-from gemma4:e2b --output adapters/lora-blue

  스모크:
    ... --max-steps 4

  merge → GGUF → Ollama (추론 속도·RAM 개선):
    python scripts/merge_peft_export_gguf_ollama.py --help

학습 설정 (개요):
  베이스: --model-id (HF). 양자화: CUDA만 QLoRA 4-bit.
  LoRA: Gemma4는 target linear; 그 외 q_proj,v_proj,k_proj,o_proj.
  epochs=5, lr=2e-4, max_seq=2048 (SFTConfig)

로더: AutoModelForCausalLM 을 먼저 시도하고, 실패 시에만 qwen3_5 에 대해 ImageTextToText 폴백.
  텍스트 SFT에는 HF 텍스트 전용 Instruct/CausalLM 체크포인트를 쓰는 것이 가장 안전하다.

데이터:
  - 기본(JSONL instruction/input/output): TRL 대화형 prompt-completion — user 메시지 + assistant(JSON).
    completion 구간에만 loss (completion_only_loss). Qwen3.5 챗 템플릿과 TRL assistant_mask 불일치를 피함.
  - --dataset-format messages: 기존 `messages` 컬럼 + assistant_only_loss(가능 시).
"""

import os
import shutil
import sys
import time
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import torch
import argparse
import subprocess
from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    PreTrainedTokenizerBase,
    TrainerCallback,
    TrainerControl,
    TrainerState,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training
)
from trl import SFTConfig, SFTTrainer
from datasets import load_dataset

# 기본 HF 베이스 (--model-id 생략 시). Gemma·4B 등은 CLI에서 --model-id 지정.
DEFAULT_MODEL_ID = "Qwen/Qwen3.5-2B"

# 스크립트 전용 — 기본 출력 폴더 (.env 미사용)
LORA_DEFAULT_OUTPUT_BY_ROLE = {
    "red": "./adapters/lora-red",
    "judge": "./adapters/lora-judge",
    "blue": "./adapters/lora-blue",
}


def _lora_config_for_gemma4() -> LoraConfig:
    """
    Gemma 4는 attention/MLP 프로젝션이 Gemma4ClippableLinear 래퍼이며,
    PEFT는 nn.Linear가 아닌 모듈에 LoRA를 붙일 수 없다.
    래퍼 내부의 실제 Linear(부모 속성명 보통 `linear`)만 타겟한다.
    lm_head가 단독 Linear인 경우 이름이 `linear`가 아니라서 여기서는 걸리지 않는다.
    """
    return LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.1,
        target_modules=["linear"],
        exclude_modules=["lm_head"],
        task_type="CAUSAL_LM",
        bias="none",
    )


def _default_lora_config() -> LoraConfig:
    """일반 Llama/Gemma(구버전) 등 nn.Linear 프로젝션."""
    return LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.1,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        task_type="CAUSAL_LM",
        bias="none",
    )


def _pick_lora_config(model) -> LoraConfig:
    arch = getattr(model.config, "architectures", None) or []
    mtype = str(getattr(model.config, "model_type", "") or "").lower()
    if mtype == "gemma4" or any("Gemma4" in str(a) for a in arch):
        print("[LoRA] Gemma 4 감지: target_modules=['linear'] (Gemma4ClippableLinear 내부 Linear)")
        return _lora_config_for_gemma4()
    print("[LoRA] 기본: target_modules=q_proj,v_proj,k_proj,o_proj")
    return _default_lora_config()


def _unsupported_qwen35_transformers_hint(model_id: str, cause: BaseException) -> RuntimeError:
    """구버전 transformers가 qwen3_5 를 CONFIG_MAPPING 에 등록하지 않을 때 안내."""
    try:
        import transformers as _tf

        ver = getattr(_tf, "__version__", "?")
    except Exception:
        ver = "?"
    return RuntimeError(
        f"모델 `{model_id}` 는 architecture `qwen3_5` 를 씁니다. "
        f"현재 transformers({ver}) 가 이 타입을 인식하지 못합니다.\n\n"
        "Colab 등에서는 다음으로 업그레이드하세요:\n"
        "  pip install -U 'transformers>=5.3.0'\n"
        "최신 릴리스로도 안 되면 소스 설치:\n"
        "  pip install -U git+https://github.com/huggingface/transformers.git\n\n"
        f"(원인: {cause})"
    )


def _load_base_model(model_id: str, use_quantization: bool, device_type: str):
    """
    텍스트 SFT에는 CausalLM 로딩이 맞다. 실패 시에만 qwen3_5 에 한해 ImageTextToText 폴백.
    """
    _trust = {"trust_remote_code": True}
    try:
        cfg = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
    except (ValueError, KeyError) as e:
        msg = str(e).lower()
        if "qwen3_5" in msg or "does not recognize" in msg:
            raise _unsupported_qwen35_transformers_hint(model_id, e) from e
        raise
    mt = str(getattr(cfg, "model_type", "") or "").lower()

    def _from_cls(ModelCls):
        if use_quantization:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
            return ModelCls.from_pretrained(
                model_id,
                quantization_config=bnb_config,
                device_map="auto",
                **_trust,
            )
        model = ModelCls.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            device_map="auto" if device_type == "cpu" else None,
            **_trust,
        )
        if device_type == "mps":
            model = model.to("mps")
        return model

    try:
        print("[로드] AutoModelForCausalLM 시도 (텍스트 SFT 권장)")
        return _from_cls(AutoModelForCausalLM)
    except Exception as e:
        print(f"[로드] CausalLM 실패: {type(e).__name__}: {e}")
        if mt == "qwen3_5":
            from transformers import AutoModelForImageTextToText

            print("[로드] 폴백: AutoModelForImageTextToText (멀티모델 — 텍스트 전용 HF id 사용 권장)")
            return _from_cls(AutoModelForImageTextToText)
        raise


def _trl_supports_assistant_only_loss(tokenizer) -> bool:
    """TRL이 tokenizer.chat_template 에 assistant_mask 패치를 적용할 수 있는지 검사."""
    try:
        from trl.chat_template_utils import get_training_chat_template

        get_training_chat_template(tokenizer)
    except ValueError:
        return False
    return True


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


def _cuda_use_bf16_training() -> bool:
    """
    A100 등 Ampere+ 에서 bf16 권장. fp16+GradScaler 경로와 QLoRA/bnb 쪽 bf16 그래디언트가 겹치면
    unscale 단계에서 NotImplementedError 가 날 수 있음 → bf16=True, fp16=False 로 통일.
    Turing(T4) 등은 보통 False → 기존처럼 fp16.
    """
    if not torch.cuda.is_available():
        return False
    try:
        return bool(torch.cuda.is_bf16_supported())
    except Exception:
        return False


def _messages_from_row(instruction: str, input_text: str, output_text: str) -> list[dict]:
    """JSONL 한 행 → TRL conversational (`messages`) 형식."""
    user_content = f"{instruction}\n{input_text}".strip()
    return [
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": output_text},
    ]


def _chat_text_from_row(
    tokenizer: PreTrainedTokenizerBase,
    instruction: str,
    input_text: str,
    output_text: str,
) -> str:
    """JSONL 한 행 -> chat_template 렌더 문자열(text)."""
    messages = _messages_from_row(instruction, input_text, output_text)
    return tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )


def _prompt_completion_strings_from_row(
    tokenizer: PreTrainedTokenizerBase,
    instruction: str,
    input_text: str,
    output_text: str,
) -> dict[str, str]:
    """
    JSONL 한 행 → 문자열 prompt / completion.

    chat_template 로 렌더한 전체 문자열에서, user-only(+generation prompt) 접두사와 나머지(assistant 구간)를 나눈다.
    prompt + completion 이 한 번에 토크나이즈될 때와 문자열 합이 일치해 TRL completion_mask 와 맞추기 유리하다.
    """
    user_content = f"{instruction}\n{input_text}".strip()
    messages_user = [{"role": "user", "content": user_content}]
    messages_full = [
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": output_text},
    ]
    prompt_text = tokenizer.apply_chat_template(
        messages_user,
        tokenize=False,
        add_generation_prompt=True,
    )
    full_text = tokenizer.apply_chat_template(
        messages_full,
        tokenize=False,
        add_generation_prompt=False,
    )
    if not full_text.startswith(prompt_text):
        raise ValueError(
            "chat_template 렌더 결과가 접두사 불일치입니다. tokenizer/chat_template 버전을 확인하세요."
        )
    return {"prompt": prompt_text, "completion": full_text[len(prompt_text) :]}


def _print_merge_gguf_hint(*, model_id: str, adapter_root: str) -> None:
    """ollama create FROM+ADAPTER 실패 시 HF 병합 → GGUF 안내."""
    print(
        "\n[안내] FROM+ADAPTER 등록이 안 되는 경우(예: unsupported architecture):\n"
        "  로컬에서 HF merge → llama.cpp GGUF → ollama create 가 안정적입니다.\n"
        "  (llama.cpp 경로·이 Mac 고정값은 scripts/merge_peft_export_gguf_ollama.py 상단 [필독] 참고)\n"
        "  예시 (프로젝트 루트에서, --llama-cpp 는 해당 파일의 절대 경로 사용):\n"
        f"  python scripts/merge_peft_export_gguf_ollama.py \\\n"
        f"    --base-model {model_id} \\\n"
        f"    --adapter {adapter_root} \\\n"
        "    --merged-hf exports/merged-hf \\\n"
        "    --llama-cpp '/Users/parkjoyeong/Desktop/Park Joyeong/Class/Projects/3. final/llama.cpp' \\\n"
        "    --gguf-out exports/model-f16.gguf \\\n"
        "    --outtype f16 \\\n"
        "    --ollama-model my-blue-merged\n",
        flush=True,
    )


def train_role_adapter(
    role: str,
    train_file: str,
    output_dir: str,
    *,
    model_id: str,
    ollama_from: str | None = None,
    max_steps: int | None = None,
    assistant_only_loss: bool = True,
    dataset_format: str = "prompt_completion",
    completion_only_loss: bool = True,
    val_file: str | None = None,
):
    """
    역할별 LoRA 어댑터 학습 및 (선택) Ollama Modelfile/등록.
    CUDA / MPS / CPU 환경을 자동 감지하여 설정을 분기한다.
    max_steps > 0 이면 해당 스텝만 돌리고 종료(스모크/디버그용).
    ollama_from 이 있으면 Modelfile의 FROM 및 ollama create 시도.
    dataset_format prompt_completion: completion(JSON)에만 loss — Blue 목표에 맞춤.
    dataset_format chat_text: messages를 chat_template 문자열(text)로 렌더해 학습.
    dataset_format messages: 구형 messages 컬럼(assistant_only_loss 템플릿 지원 시 사용).
    """
    device_type = detect_device()
    use_quantization = device_type == "cuda"

    print(f"\n" + "="*50)
    print(f"[{role.upper()}] 파인튜닝 시작")
    print(f" - HF 베이스: {model_id}")
    print(f" - 데이터: {train_file}")
    print(f" - 출력 경로: {output_dir}")
    print(f" - 감지된 디바이스: {device_type}")
    print(f" - QLoRA 4-bit 양자화: {'ON' if use_quantization else 'OFF (bitsandbytes는 CUDA 전용)'}")
    _cuda_bf16 = device_type == "cuda" and _cuda_use_bf16_training()
    if device_type == "cuda":
        print(
            f" - mixed precision: {'bf16 (GradScaler 없음)' if _cuda_bf16 else 'fp16'}"
        )
    if max_steps and max_steps > 0:
        print(f" - max_steps: {max_steps} (스모크 모드)")
    print(f" - dataset_format: {dataset_format}")
    if dataset_format == "prompt_completion":
        print(f" - completion_only_loss: {completion_only_loss} (True면 assistant JSON 구간만 loss)")
    else:
        print(f" - assistant_only_loss (요청): {assistant_only_loss}")
    print("="*50 + "\n")

    model = _load_base_model(model_id, use_quantization, device_type)

    _trust = {"trust_remote_code": True}
    tokenizer = AutoTokenizer.from_pretrained(model_id, **_trust)
    if tokenizer.pad_token_id is None:
        if tokenizer.eos_token:
            tokenizer.pad_token = tokenizer.eos_token
        elif getattr(tokenizer, "unk_token", None):
            tokenizer.pad_token = tokenizer.unk_token
    tokenizer.padding_side = "right"

    effective_assistant_only = False
    if dataset_format == "messages":
        effective_assistant_only = assistant_only_loss
        if assistant_only_loss and not _trl_supports_assistant_only_loss(tokenizer):
            print(
                "[경고] TRL이 이 chat_template에 assistant_only(loss 마스크) 패치를 적용할 수 없습니다.\n"
                "  → assistant_only_loss=False 로 전체 시퀀스 loss 로 진행합니다.\n"
                "  Blue 에이전트는 --dataset-format prompt_completion 권장."
            )
            effective_assistant_only = False
        print(f" - assistant_only_loss (실제): {effective_assistant_only}")

    # LoRA 설정 (Gemma 4는 ClippableLinear 래퍼 → 내부 linear만 타겟)
    lora_config = _pick_lora_config(model)

    if use_quantization:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    dataset = load_dataset("json", data_files=train_file)
    print(f"  학습 샘플 수: {len(dataset['train'])}")

    if dataset_format == "prompt_completion":

        def _batch_to_pc(batch: dict) -> dict:
            prompts = []
            completions = []
            for i in range(len(batch["instruction"])):
                row = _prompt_completion_strings_from_row(
                    tokenizer,
                    batch["instruction"][i],
                    batch["input"][i],
                    batch["output"][i],
                )
                prompts.append(row["prompt"])
                completions.append(row["completion"])
            return {"prompt": prompts, "completion": completions}

        train_ds = dataset["train"].map(
            _batch_to_pc,
            batched=True,
            remove_columns=dataset["train"].column_names,
        )
    elif dataset_format == "chat_text":

        def _batch_to_text(batch: dict) -> dict:
            texts = []
            for i in range(len(batch["instruction"])):
                texts.append(
                    _chat_text_from_row(
                        tokenizer,
                        batch["instruction"][i],
                        batch["input"][i],
                        batch["output"][i],
                    )
                )
            return {"text": texts}

        train_ds = dataset["train"].map(
            _batch_to_messages,
            batched=True,
            remove_columns=dataset["train"].column_names,
        )

    # ── validation 데이터셋 (선택) ───────────────────────────────────────────────
    eval_ds = None
    if val_file:
        try:
            val_dataset = load_dataset("json", data_files=val_file)
            print(f"  검증 샘플 수: {len(val_dataset['train'])}")
            if dataset_format == "prompt_completion":

                def _batch_to_pc_eval(batch: dict) -> dict:
                    prompts = []
                    completions = []
                    for i in range(len(batch["instruction"])):
                        row = _prompt_completion_strings_from_row(
                            tokenizer,
                            batch["instruction"][i],
                            batch["input"][i],
                            batch["output"][i],
                        )
                        prompts.append(row["prompt"])
                        completions.append(row["completion"])
                    return {"prompt": prompts, "completion": completions}

                eval_ds = val_dataset["train"].map(
                    _batch_to_pc_eval,
                    batched=True,
                    remove_columns=val_dataset["train"].column_names,
                )
            elif dataset_format == "chat_text":

                def _batch_to_text_eval(batch: dict) -> dict:
                    texts = []
                    for i in range(len(batch["instruction"])):
                        texts.append(
                            _chat_text_from_row(
                                tokenizer,
                                batch["instruction"][i],
                                batch["input"][i],
                                batch["output"][i],
                            )
                        )
                    return {"text": texts}

                eval_ds = val_dataset["train"].map(
                    _batch_to_text_eval,
                    batched=True,
                    remove_columns=val_dataset["train"].column_names,
                )
            else:

                def _batch_to_messages_eval(batch: dict) -> dict:
                    msgs = []
                    for i in range(len(batch["instruction"])):
                        msgs.append(
                            _messages_from_row(
                                batch["instruction"][i],
                                batch["input"][i],
                                batch["output"][i],
                            )
                        )
                    return {"messages": msgs}

                eval_ds = val_dataset["train"].map(
                    _batch_to_messages_eval,
                    batched=True,
                    remove_columns=val_dataset["train"].column_names,
                )
        except Exception as e:
            print(f"[경고] val_file 로드/전처리 실패 → train-only로 진행합니다: {e}")
            eval_ds = None
    else:

        def _batch_to_messages(batch: dict) -> dict:
            msgs = []
            for i in range(len(batch["instruction"])):
                msgs.append(
                    _messages_from_row(
                        batch["instruction"][i],
                        batch["input"][i],
                        batch["output"][i],
                    )
                )
            return {"messages": msgs}

        train_ds = dataset["train"].map(
            _batch_to_messages,
            batched=True,
            remove_columns=dataset["train"].column_names,
        )

    # SFT 설정 — 디바이스별 분기
    _completion_only = completion_only_loss if dataset_format == "prompt_completion" else False
    sft_common = dict(
        output_dir=output_dir,
        num_train_epochs=5,
        max_steps=max_steps if max_steps and max_steps > 0 else -1,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        save_strategy="epoch",
        logging_steps=10,
        max_grad_norm=0.3,
        gradient_checkpointing=True,
        max_length=2048,
        packing=False,
        report_to="none",
        use_cpu=(device_type == "cpu"),
        assistant_only_loss=effective_assistant_only,
        completion_only_loss=_completion_only,
        # eval 시 기본 배치(라이브러리 디폴트)가 크게 잡히면 OOM이 쉽게 난다.
        # val을 쓰는 경우 eval 배치를 1로 고정해 메모리 피크를 낮춘다.
        per_device_eval_batch_size=1 if eval_ds is not None else 8,
        eval_accumulation_steps=8 if eval_ds is not None else None,
    )
    if device_type == "cuda":
        sft_args = SFTConfig(
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            fp16=not _cuda_bf16,
            bf16=_cuda_bf16,
            optim="paged_adamw_32bit",
            eval_strategy="epoch" if eval_ds is not None else "no",
            **sft_common,
        )
    else:
        sft_args = SFTConfig(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=8,
            fp16=False,
            bf16=False,
            optim="adamw_torch",
            eval_strategy="epoch" if eval_ds is not None else "no",
            **sft_common,
        )

    trainer = SFTTrainer(
        model=model,
        args=sft_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,
    )
    trainer.train()

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"\n[{role.upper()}] 어댑터 저장 완료: {output_dir}")

    adapter_root = os.path.abspath(output_dir)
    # 일부 Ollama 버전은 adapter_model.safetensors 대신 model*.safetensors 만 스캔함
    _adapter_st = os.path.join(adapter_root, "adapter_model.safetensors")
    _model_st = os.path.join(adapter_root, "model.safetensors")
    if os.path.isfile(_adapter_st) and not os.path.isfile(_model_st):
        shutil.copy2(_adapter_st, _model_st)
        print(f"[Ollama 호환] model.safetensors 복사(동일 내용, adapter_model 복제)")

    if ollama_from:
        modelfile_path = os.path.join(adapter_root, "Modelfile")
        modelfile_content = f"FROM {ollama_from}\nADAPTER ."

        with open(modelfile_path, "w", encoding="utf-8") as f:
            f.write(modelfile_content)

        agent_name = f"agent-{role}"
        print("=" * 50)
        print(f"\n[Ollama {agent_name} 자동 저장 시작] (FROM {ollama_from})\n")
        try:
            result = subprocess.run(
                ["ollama", "create", agent_name, "-f", "Modelfile"],
                cwd=adapter_root,
                capture_output=True,
                text=True,
                check=True,
            )
            print(f"[Ollama] 등록 성공: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"[Ollama] 등록 실패: {e.stderr}")
            _print_merge_gguf_hint(model_id=model_id, adapter_root=adapter_root)
        except FileNotFoundError:
            print("[Ollama] 시스템에서 'ollama' 명령어를 찾을 수 없습니다. Ollama가 설치되어 있나요?")

        print(f"\n[완료 {role.upper()}] 수동 등록이 필요하면 아래를 사용하세요.\n")

        print("=" * 50)
        print("\n[Ollama 연동 가이드 - 수동]\n")
        print("어댑터 폴더로 이동한 뒤 Modelfile만 지정 (경로 공백 문제 방지):")
        print(f"  cd {adapter_root}")
        print("  ollama create <원하는모델이름> -f Modelfile\n")
        print(
            "위 방식이 unsupported architecture 등으로 실패하면 "
            "아래 merge → GGUF 경로를 사용하세요 (scripts/merge_peft_export_gguf_ollama.py --help).\n"
        )
    else:
        print("\n[Ollama] 생략 (--ollama-from 미지정). HF 어댑터만 저장되었습니다.\n")
  
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Role-based LoRA Fine-tuning")
    parser.add_argument("--role", choices=["red", "judge", "blue"], required=True, help="에이전트 역할")
    parser.add_argument("--data", required=True, help="학습용 JSONL 데이터 경로")
    parser.add_argument(
        "--model-id",
        default=DEFAULT_MODEL_ID,
        help=f"Hugging Face 베이스 모델 id (기본: {DEFAULT_MODEL_ID})",
    )
    parser.add_argument(
        "--ollama-from",
        default=None,
        help="Ollama Modelfile의 FROM 태그 (예: qwen3.5:2b). 미지정 시 Modelfile/ollama create 생략",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="어댑터 저장 경로 (미지정 시 스크립트 상단 LORA_DEFAULT_OUTPUT_BY_ROLE)",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="양수면 해당 optimizer step만 실행 후 종료 (스모크·파이프라인 검증용). 미지정이면 epoch 전체.",
    )
    parser.add_argument(
        "--dataset-format",
        choices=["prompt_completion", "chat_text", "messages"],
        default="prompt_completion",
        help="prompt_completion: completion-only(기본), chat_text: apply_chat_template 문자열, messages: 구형 messages 컬럼.",
    )
    parser.add_argument(
        "--full-sequence-loss",
        action="store_true",
        help="prompt_completion 모드에서만: completion이 아닌 전체 시퀀스에 loss.",
    )
    parser.add_argument(
        "--no-assistant-only-loss",
        action="store_true",
        help="dataset-format messages 일 때만: 전체 시퀀스 loss.",
    )
    parser.add_argument(
        "--val-data",
        default=None,
        help="검증용 JSONL 데이터 경로 (예: data/finetuning/blue_val.jsonl). 미지정 시 train-only.",
    )
    args = parser.parse_args()

    # 출력 경로 결정 (스크립트 내 기본값)
    if args.output:
        final_output = args.output
    else:
        final_output = LORA_DEFAULT_OUTPUT_BY_ROLE[args.role]

    final_output = args.output or {
        "red":   os.getenv("LORA_RED_PATH",   "./adapters/lora-red-qwen35-2b-abliterated"),
        "judge": os.getenv("LORA_JUDGE_PATH",  "./adapters/lora-judge"),
        "blue":  os.getenv("LORA_BLUE_PATH",   "./adapters/lora-blue"),
    }[args.role]

    os.makedirs(final_output, exist_ok=True)
    train_role_adapter(
        args.role,
        args.data,
        final_output,
        model_id=args.model_id,
        ollama_from=args.ollama_from,
        max_steps=args.max_steps,
        assistant_only_loss=not args.no_assistant_only_loss,
        dataset_format=args.dataset_format,
        completion_only_loss=not args.full_sequence_loss,
        val_file=args.val_data,
    )
