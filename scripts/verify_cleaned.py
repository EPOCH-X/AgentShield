"""정제 결과 검증 스크립트"""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORIG = ROOT / "data" / "finetuning" / "judge_train.jsonl"
CLEANED = sorted((ROOT / "data" / "finetuning").glob("judge_train_cleaned_*.jsonl"))[-1]

def load(path):
    items = []
    with open(path) as f:
        for line in f:
            items.append(json.loads(line))
    return items

def parse_input(item):
    text = item.get("input", "")
    parts = text.split("\n\nResponse: ", 1)
    if len(parts) == 2:
        return parts[0].replace("Prompt: ", "", 1), parts[1]
    return text, ""

def is_truncated(resp):
    s = resp.strip()
    if not s:
        return True
    end_chars = set('.\u2026!?\u201d\u201c"\')\u300d\u300f]')
    if s[-1] in end_chars:
        return False
    if ord(s[-1]) > 0x1F000:
        return False
    return True

orig = load(ORIG)
cleaned = load(CLEANED)

print(f"원본: {len(orig)}건")
print(f"정제본: {len(cleaned)}건 ({CLEANED.name})")
print(f"제거: {len(orig)-len(cleaned)}건")

# 카테고리 분포
print("\n=== 카테고리 분포 ===")
orig_cat = Counter(i["owasp_category"] for i in orig)
clean_cat = Counter(i["owasp_category"] for i in cleaned)
for cat in sorted(set(list(orig_cat) + list(clean_cat))):
    print(f"  {cat}: {orig_cat[cat]} -> {clean_cat[cat]} ({clean_cat[cat]-orig_cat[cat]:+d})")

# 라벨 분포
print("\n=== response_harm 분포 ===")
orig_h = Counter(json.loads(i["output"])["response_harm"] for i in orig)
clean_h = Counter(json.loads(i["output"])["response_harm"] for i in cleaned)
for lb in sorted(set(list(orig_h) + list(clean_h))):
    print(f"  {lb}: {orig_h[lb]} -> {clean_h[lb]} ({clean_h[lb]-orig_h[lb]:+d})")

# refusal 분포
print("\n=== refusal 분포 ===")
orig_r = Counter(json.loads(i["output"])["refusal"] for i in orig)
clean_r = Counter(json.loads(i["output"])["refusal"] for i in cleaned)
for lb in sorted(set(list(orig_r) + list(clean_r))):
    print(f"  {lb}: {orig_r[lb]} -> {clean_r[lb]} ({clean_r[lb]-orig_r[lb]:+d})")

# 잘림 잔존
trunc = 0
for item in cleaned:
    _, resp = parse_input(item)
    if is_truncated(resp):
        trunc += 1
print(f"\n=== 잘림 잔존 ===")
print(f"  정제본 잘린 응답: {trunc}건")

# 중복 잔존
prompts = []
for item in cleaned:
    p, _ = parse_input(item)
    prompts.append(p)
dup_groups = sum(1 for v in Counter(prompts).values() if v > 1)
print(f"  정제본 중복 prompt 그룹: {dup_groups}개")

# output 유효성
invalid = 0
for item in cleaned:
    try:
        out = json.loads(item["output"])
        if out["prompt_harm"] not in ("harmful", "unharmful"):
            invalid += 1
        if out["response_harm"] not in ("harmful", "unharmful"):
            invalid += 1
        if out["refusal"] not in ("refusal", "compliance"):
            invalid += 1
    except Exception:
        invalid += 1
print(f"  output 유효성 실패: {invalid}건")

# 샘플 5건 출력
print("\n=== 정제본 샘플 5건 ===")
for i, item in enumerate(cleaned[:5]):
    p, r = parse_input(item)
    out = json.loads(item["output"])
    print(f"  [{i+1}] cat={item['owasp_category']}  harm={out['response_harm']}  ref={out['refusal']}")
    print(f"      prompt: {p[:80]}...")
    print(f"      resp: {r[:80]}...")
    print()
