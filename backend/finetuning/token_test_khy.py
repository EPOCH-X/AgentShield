import os
import sys
import json
from pathlib import Path
from transformers import AutoTokenizer

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

BASE_MODEL_ID = "Qwen/Qwen3.5-2B"
DATA_PATH = PROJECT_ROOT / "data" / "finetuning" / "judge_train.jsonl"
MAX_LENGTH = 2048

tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL_ID,
    trust_remote_code=True,
)

lengths = []
over_items = []

with DATA_PATH.open("r", encoding="utf-8") as f:
    for idx, line in enumerate(f, start=1):
        if not line.strip():
            continue

        row = json.loads(line)
        messages = row["messages"]

        text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )

        token_count = len(
            tokenizer(
                text,
                add_special_tokens=False,
            ).input_ids
        )

        lengths.append(token_count)

        if token_count > MAX_LENGTH:
            over_items.append({
                "line": idx,
                "tokens": token_count,
                "overflow": token_count - MAX_LENGTH,
            })

total = len(lengths)
over_count = len(over_items)

print("\n========== TOKEN LENGTH REPORT ==========")
print(f"file: {DATA_PATH}")
print(f"total samples: {total}")
print(f"max_length: {MAX_LENGTH}")

if total:
    print(f"min tokens: {min(lengths)}")
    print(f"max tokens: {max(lengths)}")
    print(f"avg tokens: {sum(lengths) / total:.2f}")

    sorted_lengths = sorted(lengths)
    print(f"p50 tokens: {sorted_lengths[int(total * 0.50)]}")
    print(f"p90 tokens: {sorted_lengths[int(total * 0.90)]}")
    print(f"p95 tokens: {sorted_lengths[int(total * 0.95)]}")
    print(f"p99 tokens: {sorted_lengths[min(total - 1, int(total * 0.99))]}")

print("\n========== OVERFLOW ==========")
print(f"over {MAX_LENGTH}: {over_count}")
print(f"overflow ratio: {(over_count / total * 100) if total else 0:.2f}%")

if over_items:
    print("\nTop 20 longest overflow samples:")
    for item in sorted(over_items, key=lambda x: x["tokens"], reverse=True)[:20]:
        print(
            f"line={item['line']} "
            f"tokens={item['tokens']} "
            f"overflow={item['overflow']}"
        )