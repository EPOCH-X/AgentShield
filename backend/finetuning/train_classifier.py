"""
AgentShield Classifier 학습 스크립트

입력 데이터:
- prep_classifier_data_khy.py가 생성한 classifier 전용 JSON/JSONL 권장

지원 입력 구조:
1) classifier 전용 구조
{
  "category": "LLM02",
  "attack_prompt": "...",
  "target_response": "...",
  "judgment": "safe|vulnerable",
  "label": 0,
  "text": "Prompt: ...\n\nResponse: ..."
}

2) 기존 flat 구조
{
  "mutated_prompt": "...",
  "target_response": "...",
  "judgment": "safe|vulnerable"
}

label:
- safe = 0
- vulnerable = 1

중요:
- 학습 입력 text 형식은 judge_agent.py의 build_classifier_text와 동일하게 유지한다.
  Prompt: {prompt}\n\nResponse: {response}
"""

from __future__ import annotations

import argparse
import json
import os
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)


# =========================
# CONFIG
# =========================

VALID_JUDGMENTS = {"safe", "vulnerable"}

DEFAULT_MODEL_NAME = "microsoft/deberta-v3-base"
DEFAULT_INPUT_PATH = Path("data/finetuning/classifier_train_data.json")
DEFAULT_OUTPUT_DIR = Path("backend/agents/best_weights")
DEFAULT_RUN_DIR = Path("data/classifier_runs")
DEFAULT_REPORT_PATH = Path("data/finetuning/classifier_train_report.json")


# =========================
# DATA HELPERS
# =========================

def normalize_judgment(value: Any) -> str:
    value = "" if value is None else str(value).strip().lower()

    if value in VALID_JUDGMENTS:
        return value

    return ""


def label_from_judgment(judgment: str) -> int:
    judgment = normalize_judgment(judgment)

    if judgment == "safe":
        return 0

    if judgment == "vulnerable":
        return 1

    raise ValueError(f"invalid judgment: {judgment}")


def build_classifier_text(prompt: str, response: str) -> str:
    """
    backend.agents.judge_agent.build_classifier_text 와 반드시 동일하게 유지.
    """
    return f"Prompt: {prompt or ''}\n\nResponse: {response or ''}"


def load_json_or_jsonl(file_path: Path) -> List[Dict[str, Any]]:
    raw = file_path.read_text(encoding="utf-8").strip()

    if not raw:
        return []

    if file_path.suffix.lower() == ".jsonl":
        rows: List[Dict[str, Any]] = []

        for line_no, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL parse error at line {line_no}: {exc}") from exc

        return rows

    data = json.loads(raw)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("data", "items", "samples", "records"):
            if isinstance(data.get(key), list):
                return data[key]

    raise ValueError(
        "입력 파일은 JSON list, JSONL, 또는 data/items/samples/records list를 가진 dict여야 합니다."
    )


def extract_text_label(item: Dict[str, Any]) -> Tuple[str, int] | None:
    """
    다양한 구조에서 classifier text와 label을 추출한다.
    """

    # 1) prep_classifier_data_khy.py 출력 구조: text + label
    if "text" in item and "label" in item:
        text = str(item.get("text", "") or "")
        label = int(item.get("label"))

        if text.strip() and label in {0, 1}:
            return text, label

    # 2) prep_classifier_data_khy.py 출력 구조: attack_prompt + target_response + judgment
    if "attack_prompt" in item and "target_response" in item and ("judgment" in item or "judgement" in item):
        prompt = str(item.get("attack_prompt", "") or "")
        response = str(item.get("target_response", "") or "")
        judgment = normalize_judgment(item.get("judgment", item.get("judgement", "")))

        if prompt.strip() and response.strip() and judgment:
            return build_classifier_text(prompt, response), label_from_judgment(judgment)

    # 3) 기존 flat 구조: mutated_prompt + target_response + judgment
    if "mutated_prompt" in item and "target_response" in item and ("judgment" in item or "judgement" in item):
        prompt = str(item.get("mutated_prompt", "") or "")
        response = str(item.get("target_response", "") or "")
        judgment = normalize_judgment(item.get("judgment", item.get("judgement", "")))

        if prompt.strip() and response.strip() and judgment:
            return build_classifier_text(prompt, response), label_from_judgment(judgment)

    # 4) 혹시 prompt 키로 저장된 경우
    if "prompt" in item and "target_response" in item and ("judgment" in item or "judgement" in item):
        prompt = str(item.get("prompt", "") or "")
        response = str(item.get("target_response", "") or "")
        judgment = normalize_judgment(item.get("judgment", item.get("judgement", "")))

        if prompt.strip() and response.strip() and judgment:
            return build_classifier_text(prompt, response), label_from_judgment(judgment)

    return None


def load_classifier_dataset(file_path: Path) -> Tuple[List[str], List[int], Dict[str, Any]]:
    rows = load_json_or_jsonl(file_path)

    texts: List[str] = []
    labels: List[int] = []
    skipped: List[Dict[str, Any]] = []

    for idx, item in enumerate(rows):
        if not isinstance(item, dict):
            skipped.append({"index": idx, "reason": "item_not_dict"})
            continue

        extracted = extract_text_label(item)

        if extracted is None:
            skipped.append({"index": idx, "reason": "cannot_extract_text_label"})
            continue

        text, label = extracted
        texts.append(text)
        labels.append(label)

    report = {
        "input_path": str(file_path),
        "raw_rows": len(rows),
        "usable_rows": len(texts),
        "skipped_count": len(skipped),
        "skipped_examples": skipped[:30],
        "label_distribution": dict(Counter(labels)),
        "judgment_distribution": {
            "safe": int(Counter(labels).get(0, 0)),
            "vulnerable": int(Counter(labels).get(1, 0)),
        },
        "text_format": "Prompt: {prompt}\\n\\nResponse: {response}",
    }

    if len(set(labels)) < 2:
        raise ValueError(f"safe/vulnerable 두 클래스가 모두 필요합니다. label_distribution={report['label_distribution']}")

    return texts, labels, report


# =========================
# TRAINER
# =========================

def tokenize_dataset(dataset: Dataset, tokenizer: AutoTokenizer, max_length: int) -> Dataset:
    def tokenize_func(batch: Dict[str, List[Any]]) -> Dict[str, Any]:
        return tokenizer(
            batch["text"],
            padding="max_length",
            truncation=True,
            max_length=max_length,
        )

    tokenized = dataset.map(tokenize_func, batched=True)
    return tokenized.remove_columns(["text"])


def compute_metrics(eval_pred: Any) -> Dict[str, float]:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        preds,
        average="binary",
        zero_division=0,
    )

    return {
        "accuracy": float(accuracy_score(labels, preds)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def build_training_arguments(
    *,
    run_dir: Path,
    learning_rate: float,
    epochs: float,
    batch_size: int,
    grad_accum: int,
    weight_decay: float,
    warmup_ratio: float,
    bf16: bool,
    fp16: bool,
    save_total_limit: int,
    logging_steps: int,
) -> TrainingArguments:
    common_args = dict(
        output_dir=str(run_dir),
        learning_rate=learning_rate,
        warmup_ratio=warmup_ratio,
        max_grad_norm=1.0,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=epochs,
        weight_decay=weight_decay,
        adam_epsilon=1e-6,
        bf16=bf16,
        fp16=fp16,
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=save_total_limit,
        logging_steps=logging_steps,
        report_to="none",
        seed=42,
        data_seed=42,
    )

    try:
        return TrainingArguments(
            eval_strategy="epoch",
            **common_args,
        )
    except TypeError:
        return TrainingArguments(
            evaluation_strategy="epoch",
            **common_args,
        )


class LLMJudgeTrainer:
    """LLM 응답의 취약성 여부를 확률로 판정하는 모델 학습 클래스"""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        local_path: str | Path | None = None,
        resume: bool = False,
    ) -> None:
        """
        resume=False:
            항상 base model에서 새로 학습 시작.
        resume=True:
            local_path가 존재하면 거기서 이어서 학습.
        """

        local_path = Path(local_path) if local_path else None

        if resume and local_path and local_path.exists():
            print(f"[로드] 기존 classifier weights: {local_path}")
            load_path = str(local_path)
        else:
            print(f"[로드] base model: {model_name}")
            load_path = model_name

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(load_path, use_fast=True)
        except Exception:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)

        self.model = AutoModelForSequenceClassification.from_pretrained(
            load_path,
            num_labels=2,
        )

    def train(
        self,
        texts: List[str],
        labels: List[int],
        *,
        output_dir: Path,
        run_dir: Path,
        test_size: float = 0.2,
        seed: int = 42,
        max_length: int = 512,
        learning_rate: float = 1e-6,
        epochs: float = 50,
        batch_size: int = 8,
        grad_accum: int = 2,
        weight_decay: float = 0.01,
        warmup_ratio: float = 0.1,
        bf16: bool = False,
        fp16: bool = False,
        save_total_limit: int = 2,
        logging_steps: int = 20,
    ) -> Dict[str, Any]:
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts,
            labels,
            test_size=test_size,
            random_state=seed,
            stratify=labels,
        )

        train_dataset = Dataset.from_dict({
            "text": train_texts,
            "label": train_labels,
        })
        val_dataset = Dataset.from_dict({
            "text": val_texts,
            "label": val_labels,
        })

        train_dataset = tokenize_dataset(train_dataset, self.tokenizer, max_length)
        val_dataset = tokenize_dataset(val_dataset, self.tokenizer, max_length)

        training_args = build_training_arguments(
            run_dir=run_dir,
            learning_rate=learning_rate,
            epochs=epochs,
            batch_size=batch_size,
            grad_accum=grad_accum,
            weight_decay=weight_decay,
            warmup_ratio=warmup_ratio,
            bf16=bf16,
            fp16=fp16,
            save_total_limit=save_total_limit,
            logging_steps=logging_steps,
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
        )

        trainer.train()
        metrics = trainer.evaluate()

        output_dir.mkdir(parents=True, exist_ok=True)
        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)

        return {
            "train_count": len(train_texts),
            "val_count": len(val_texts),
            "metrics": metrics,
            "output_dir": str(output_dir),
            "run_dir": str(run_dir),
        }

    @torch.no_grad()
    def predict_probability(
        self,
        prompt: str,
        response: str,
        max_length: int = 512,
    ) -> Dict[str, float]:
        self.model.eval()
        device = next(self.model.parameters()).device

        combined_text = build_classifier_text(prompt, response)

        inputs = self.tokenizer(
            combined_text,
            return_tensors="pt",
            truncation=True,
            max_length=max_length,
        )
        inputs = {key: value.to(device) for key, value in inputs.items()}

        outputs = self.model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0].detach().cpu().tolist()

        return {
            "safe_probability": round(float(probs[0]) * 100, 2),
            "vulnerable_probability": round(float(probs[1]) * 100, 2),
        }


# =========================
# REPORT
# =========================

def save_report(report: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train DeBERTa classifier for AgentShield."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"classifier train data path, default={DEFAULT_INPUT_PATH}",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"final model output dir, default={DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=DEFAULT_RUN_DIR,
        help=f"trainer checkpoint/log dir, default={DEFAULT_RUN_DIR}",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"training report path, default={DEFAULT_REPORT_PATH}",
    )
    parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    parser.add_argument("--resume", action="store_true", help="resume from output-dir if it exists")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=3e-6)
    parser.add_argument("--epochs", type=float, default=10)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--grad-accum", type=int, default=4)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--save-total-limit", type=int, default=2)
    parser.add_argument("--logging-steps", type=int, default=20)
    parser.add_argument("--bf16", action="store_true")
    parser.add_argument("--fp16", action="store_true")
    parser.add_argument("--prepare-only", action="store_true", help="only load data and write report")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    texts, labels, data_report = load_classifier_dataset(args.input)

    print("\n[데이터 로드 완료]")
    print(f"input: {args.input}")
    print(f"usable_rows: {data_report['usable_rows']}")
    print(f"label_distribution: {data_report['label_distribution']}")
    print(f"skipped_count: {data_report['skipped_count']}")

    final_report: Dict[str, Any] = {
        "data": data_report,
        "training": None,
    }

    if args.prepare_only:
        save_report(final_report, args.report)
        print(f"\n[prepare-only 완료] report: {args.report}")
        return

    trainer = LLMJudgeTrainer(
        model_name=args.model_name,
        local_path=args.output_dir,
        resume=args.resume,
    )

    train_report = trainer.train(
        texts,
        labels,
        output_dir=args.output_dir,
        run_dir=args.run_dir,
        test_size=args.test_size,
        seed=args.seed,
        max_length=args.max_length,
        learning_rate=args.learning_rate,
        epochs=args.epochs,
        batch_size=args.batch_size,
        grad_accum=args.grad_accum,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        bf16=args.bf16,
        fp16=args.fp16,
        save_total_limit=args.save_total_limit,
        logging_steps=args.logging_steps,
    )

    final_report["training"] = train_report
    save_report(final_report, args.report)

    print("\n[학습 완료]")
    print(f"output_dir: {args.output_dir}")
    print(f"run_dir: {args.run_dir}")
    print(f"report: {args.report}")
    print(f"metrics: {train_report['metrics']}")


if __name__ == "__main__":
    main()
