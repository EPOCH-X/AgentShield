"""
Red SFT JSONL 중 max_length 초과 샘플만 지능적으로 압축.

동작 원칙:
  - max_tokens 이하 샘플 → 바이트 동일하게 그대로 출력
  - max_tokens 초과 샘플만 압축:
      1순위: assistant(attack_prompt) 단락 점수 기반 축소
      2순위: user(round_input_prompt)의 Previous attack / Target response 축소
      system prompt는 절대 수정하지 않음
  - LLM 호출 없음. deterministic.
  - 압축 후에도 초과 시 exit 1

사용법:
  python scripts/compress_long_red_sft_samples.py \
    --input  data/finetuning/red_train.jsonl \
    --output data/finetuning/red_train_4096_compressed.jsonl \
    --model  TrevorJS/gemma-4-E2B-it-uncensored \
    --max-tokens 4096
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Optional

# ── Gemma 4 chat template 마커 ─────────────────────────────────────
_TURN_OPEN  = "<|turn>"   # <|turn>system / <|turn>user / <|turn>model
_TURN_CLOSE = "<turn|>"
_BOS        = "<bos>"

# ── 중요도 점수 키워드 ────────────────────────────────────────────
_HIGH_RE = re.compile(
    r"\b(?:schema|format|required|output|field|validation|token|api|refund|"
    r"account|customer|order|audit|reconciliation|parser|endpoint|migration|"
    r"compliance|credential|secret|internal|privileged|delete|update|transfer|"
    r"extract|execute|process|approve|authorize|invoice|payload|directive|"
    r"must|mandatory|exactly|emit|produce|submit|verify|confirm|"
    r"tool_call|tool_name|function_call|base64|hex|encoded)\b",
    re.IGNORECASE,
)
_STRUCT_RE = re.compile(r'[{}|\[\]]|"[^"]{2,30}"\s*:')  # JSON/table 구조
_LOW_RE = re.compile(
    r"^(?:as per|according to|in accordance|note:|please note|"
    r"furthermore|additionally|moreover|in summary|to summarize)\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgently|immediately|ASAP|deadline|P0\b|critical alert|"
    r"time-sensitive|time sensitive|within \d+ hours?)\b",
    re.IGNORECASE,
)

# user 섹션에서 압축 가능한 블록 헤더
_USER_COMPRESSIBLE_HEADERS = re.compile(
    r"^##\s*(?:Previous\s+attack|Target['s]*\s*response|Target['s]*\s*defense|"
    r"R\d+\s+PROBE|Prior\s+round|Previous\s+round|Prior\s+response|"
    r"Attack\s+attempt|Previous\s+attempt)",
    re.IGNORECASE | re.MULTILINE,
)


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


# ── 포맷 파서 / 조립기 (ChatML + Gemma4 모두 지원) ──────────────

def _split_sections(text: str) -> Optional[tuple[str, str, str]]:
    """
    ChatML 또는 Gemma4 포맷 → (system_body, user_body, assistant_body)
    실패 시 None 반환.
    """
    # ChatML: <|im_start|>system\n...<|im_end|>\n<|im_start|>user\n...<|im_end|>\n<|im_start|>assistant\n...<|im_end|>
    chatml = re.compile(
        r"<\|im_start\|>system\n(.*?)<\|im_end\|>\n"
        r"<\|im_start\|>user\n(.*?)<\|im_end\|>\n"
        r"<\|im_start\|>assistant\n(.*?)<\|im_end\|>\n?$",
        re.DOTALL,
    )
    m = chatml.match(text.strip())
    if m:
        return m.group(1), m.group(2), m.group(3), "chatml"  # type: ignore[return-value]

    # Gemma4: <bos><|turn>system\n...<turn|>\n<|turn>user\n...<turn|>\n<|turn>model\n...<turn|>
    gemma4 = re.compile(
        r"<bos><\|turn>system\n(.*?)<turn\|>\n"
        r"<\|turn>user\n(.*?)<turn\|>\n"
        r"<\|turn>model\n(.*?)<turn\|>\n?$",
        re.DOTALL,
    )
    m = gemma4.match(text.strip())
    if m:
        return m.group(1), m.group(2), m.group(3), "gemma4"  # type: ignore[return-value]

    return None


def _assemble(system: str, user: str, assistant: str, fmt: str = "chatml") -> str:
    if fmt == "gemma4":
        return (
            f"<bos><|turn>system\n{system}<turn|>\n"
            f"<|turn>user\n{user}<turn|>\n"
            f"<|turn>model\n{assistant}<turn|>\n"
        )
    # ChatML (기본)
    return (
        f"<|im_start|>system\n{system}<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant}<|im_end|>\n"
    )


# ── 단락 점수 ─────────────────────────────────────────────────────

def _score_paragraph(para: str) -> float:
    """높을수록 중요. 낮은 점수 단락을 먼저 제거한다."""
    if not para.strip():
        return -1.0  # 빈 줄은 최저

    score = 0.0
    score += len(_HIGH_RE.findall(para)) * 3.0
    score += len(_STRUCT_RE.findall(para)) * 2.0

    if _LOW_RE.search(para):
        score -= 5.0
    score -= len(_URGENCY_RE.findall(para)) * 2.0

    # 마크다운 헤더는 보존 (섹션 구조)
    if re.match(r"^#{1,4}\s", para.strip()):
        score += 10.0

    # JSON 블록 (```json) 보존
    if re.search(r"```(?:json|JSON)", para):
        score += 8.0

    # 파이프 테이블 행 보존
    if para.strip().startswith("|"):
        score += 4.0

    # 짧은 문장은 약간 불리 (반복 예시가 많음)
    if len(para.strip()) < 60:
        score -= 1.0

    return score


def _compress_by_paragraphs(text: str, tok, budget_tokens: int) -> str:
    """
    단락 단위로 점수를 매기고, 낮은 점수부터 제거해 budget 이하로 만든다.
    첫 단락(섹션 제목)과 마지막 단락(최종 지시)은 항상 보존.
    """
    paras = re.split(r"\n{2,}", text)
    if len(paras) <= 2:
        # 단락이 너무 적으면 문장 단위로 줄임
        return _compress_by_sentences(text, tok, budget_tokens)

    scored = [(i, p, _score_paragraph(p)) for i, p in enumerate(paras)]
    n = len(scored)

    # 첫/마지막 단락은 pin (제거 불가)
    pinned = {0, n - 1}

    # 점수 낮은 순 정렬 (pinned 제외)
    removable = sorted(
        [(score, i) for i, _, score in scored if i not in pinned],
    )

    kept = list(range(n))
    for _, idx in removable:
        candidate = [paras[i] for i in sorted(kept) if i != idx]
        candidate_text = "\n\n".join(candidate)
        if len(tok.encode(candidate_text, add_special_tokens=False)) <= budget_tokens:
            kept.remove(idx)
            return candidate_text
        kept_without = [i for i in kept if i != idx]
        joined = "\n\n".join(paras[i] for i in sorted(kept_without))
        if len(tok.encode(joined, add_special_tokens=False)) <= budget_tokens:
            kept = kept_without

    result = "\n\n".join(paras[i] for i in sorted(kept))
    if len(tok.encode(result, add_special_tokens=False)) > budget_tokens:
        result = _compress_by_sentences(result, tok, budget_tokens)
    return result


def _compress_by_sentences(text: str, tok, budget_tokens: int) -> str:
    """
    문장 단위로 줄임. 마지막 2문장은 항상 보존.
    """
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if len(sentences) <= 3:
        # 문장도 적으면 그냥 토큰 기준으로 자름 (최후 수단)
        encoded = tok.encode(text, add_special_tokens=False)
        return tok.decode(encoded[:budget_tokens], skip_special_tokens=False)

    tail = sentences[-2:]  # 마지막 2문장 보존
    body = sentences[:-2]

    while body:
        candidate = " ".join(body) + " " + " ".join(tail)
        if len(tok.encode(candidate, add_special_tokens=False)) <= budget_tokens:
            return candidate
        body.pop(0)  # 앞에서 제거

    return " ".join(tail)


def _compress_user_section(user: str, tok, budget_tokens: int) -> str:
    """
    user(round_input_prompt)에서 Previous attack / Target response 블록을 축소.
    """
    # 섹션을 ## 헤더 기준으로 분리
    parts = re.split(r"(^##\s+[^\n]+)", user, flags=re.MULTILINE)
    if len(parts) <= 1:
        # 헤더 없으면 전체를 절반으로
        encoded = tok.encode(user, add_special_tokens=False)
        return tok.decode(encoded[: budget_tokens // 2], skip_special_tokens=False)

    result_parts = []
    i = 0
    while i < len(parts):
        chunk = parts[i]
        header_match = re.match(r"^##\s+(Previous|Target|R\d+\s+PROBE|Prior|Attack attempt)", chunk, re.IGNORECASE)
        if header_match and i + 1 < len(parts):
            # 이 블록은 압축 대상 — 앞 400자만 유지
            body = parts[i + 1]
            short_body = body[:400].rstrip() + ("\n...[truncated for compression]\n" if len(body) > 400 else "")
            result_parts.append(chunk + "\n" + short_body)
            i += 2
        else:
            result_parts.append(chunk)
            i += 1

    compressed = "\n".join(result_parts)
    if len(tok.encode(compressed, add_special_tokens=False)) > budget_tokens:
        # 그래도 길면 절반 토큰 자름
        encoded = tok.encode(compressed, add_special_tokens=False)
        compressed = tok.decode(encoded[:budget_tokens], skip_special_tokens=False)
    return compressed


def compress_sample(text: str, tok, max_tokens: int) -> tuple[str, int, int]:
    """
    초과 샘플을 압축. (compressed_text, before_tokens, after_tokens) 반환.
    """
    before = len(tok.encode(text, add_special_tokens=False))
    sections = _split_sections(text)
    if sections is None:
        # 파싱 실패 — 단순 토큰 절단 (최후 수단)
        encoded = tok.encode(text, add_special_tokens=False)
        compressed = tok.decode(encoded[:max_tokens], skip_special_tokens=False)
        return compressed, before, len(tok.encode(compressed, add_special_tokens=False))

    system, user, assistant, fmt = sections
    sys_tokens  = len(tok.encode(system,    add_special_tokens=False))
    user_tokens = len(tok.encode(user,      add_special_tokens=False))
    ast_tokens  = len(tok.encode(assistant, add_special_tokens=False))
    # 마커 오버헤드 (bos + 마커 3개 × ~4토큰)
    marker_overhead = 20
    available = max_tokens - sys_tokens - marker_overhead

    # ── 1순위: assistant 압축 ──────────────────────────────────
    ast_budget = available - user_tokens
    if ast_budget < 200:
        # user도 너무 길면 user도 같이 줄여야
        ast_budget = available // 2

    compressed_ast = _compress_by_paragraphs(assistant, tok, ast_budget)
    new_ast_tokens = len(tok.encode(compressed_ast, add_special_tokens=False))

    # ── 2순위: 그래도 부족하면 user 압축 ─────────────────────
    remaining_for_user = available - new_ast_tokens
    if remaining_for_user < user_tokens:
        compressed_user = _compress_user_section(user, tok, remaining_for_user)
    else:
        compressed_user = user

    result = _assemble(system, compressed_user, compressed_ast, fmt)
    after = len(tok.encode(result, add_special_tokens=False))

    # ── 최후 수단: 아직 초과면 assistant를 문장 단위로 더 줄임 ──
    if after > max_tokens:
        hard_ast_budget = max_tokens - sys_tokens - len(tok.encode(compressed_user, add_special_tokens=False)) - marker_overhead
        if hard_ast_budget > 100:
            compressed_ast = _compress_by_sentences(compressed_ast, tok, hard_ast_budget)
        result = _assemble(system, compressed_user, compressed_ast, fmt)
        after = len(tok.encode(result, add_special_tokens=False))

    return result, before, after


# ── 메인 ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Red SFT JSONL 초과 샘플 압축")
    parser.add_argument("--input",      default="data/finetuning/red_train.jsonl")
    parser.add_argument("--output",     default="data/finetuning/red_train_4096_compressed.jsonl")
    parser.add_argument("--model",      default="TrevorJS/gemma-4-E2B-it-uncensored")
    parser.add_argument("--max-tokens", type=int, default=4096)
    args = parser.parse_args()

    from transformers import AutoTokenizer
    print(f"[tokenizer] {args.model} 로드 중...")
    tok = AutoTokenizer.from_pretrained(args.model)
    print(f"[tokenizer] 완료")

    # ── 입력 읽기 ─────────────────────────────────────────────
    rows: list[tuple[str, dict]] = []   # (raw_line, parsed)
    parse_errors: list[int] = []
    with open(args.input, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            try:
                d = json.loads(line)
                rows.append((line.rstrip("\n"), d))
            except json.JSONDecodeError as e:
                parse_errors.append(line_no)
                print(f"[ERROR] line {line_no}: JSON parse failed — {e}")

    if parse_errors:
        print(f"[FAIL] JSON 파싱 오류 {len(parse_errors)}건. 중단.")
        sys.exit(1)

    # ── 토큰 수 계산 ─────────────────────────────────────────
    token_counts = [
        len(tok.encode(d["text"], add_special_tokens=False))
        for _, d in rows
    ]

    over_indices = [i for i, tc in enumerate(token_counts) if tc > args.max_tokens]
    under_indices = [i for i, tc in enumerate(token_counts) if tc <= args.max_tokens]

    print(f"\n입력 총 {len(rows)}건 | 초과(>{args.max_tokens}): {len(over_indices)}건 | 이하: {len(under_indices)}건")

    # ── 4096 이하 샘플 해시 기록 (변경 여부 검증용) ──────────
    original_hashes = {i: _md5(rows[i][0]) for i in under_indices}

    # ── 압축 실행 ─────────────────────────────────────────────
    compressed_results: list[dict] = []  # {line_no, before, after, ok}
    output_rows: list[str] = []

    for i, (raw_line, d) in enumerate(rows):
        if i not in over_indices:
            output_rows.append(raw_line)
            continue

        line_no = i + 1
        text = d["text"]
        compressed_text, before_tok, after_tok = compress_sample(text, tok, args.max_tokens)
        ok = after_tok <= args.max_tokens

        new_d = {**d, "text": compressed_text}
        output_rows.append(json.dumps(new_d, ensure_ascii=False))
        compressed_results.append({
            "line_no": line_no,
            "category": f"{d.get('_category','?')}/{d.get('_subcategory','?')}",
            "before_tokens": before_tok,
            "after_tokens": after_tok,
            "ok": ok,
        })
        status = "✓" if ok else "✗ STILL OVER"
        print(f"  line {line_no:3d} [{d.get('_category','?')}/{d.get('_subcategory','?')}] "
              f"{before_tok} → {after_tok} tok  {status}")

    # ── 출력 쓰기 ─────────────────────────────────────────────
    with open(args.output, "w", encoding="utf-8") as f:
        for line in output_rows:
            f.write(line + "\n")

    # ── 검증: 4096 이하 샘플 바이트 동일 여부 ────────────────
    changed_safe = []
    with open(args.output, encoding="utf-8") as f:
        out_lines = [l.rstrip("\n") for l in f]
    for i in under_indices:
        new_hash = _md5(out_lines[i])
        if new_hash != original_hashes[i]:
            changed_safe.append(i + 1)
    if changed_safe:
        print(f"\n[ERROR] max_tokens 이하 샘플이 변경됨: lines {changed_safe}")
        sys.exit(1)
    print(f"\n  ✓ {len(under_indices)}건 미초과 샘플 — 바이트 동일 확인")

    # ── 최종 통계 ─────────────────────────────────────────────
    still_over = [r for r in compressed_results if not r["ok"]]
    before_max = max(r["before_tokens"] for r in compressed_results) if compressed_results else 0
    after_max  = max(r["after_tokens"]  for r in compressed_results) if compressed_results else 0

    # 출력 파일 카테고리 분포
    from collections import Counter
    out_cats: Counter = Counter()
    with open(args.output, encoding="utf-8") as f:
        for line in f:
            d2 = json.loads(line)
            out_cats[f"{d2.get('_category','?')}/{d2.get('_subcategory','?')}"] += 1

    print(f"""
╔══════════════════════════════════════════════════╗
  압축 결과 요약
  input_total        : {len(rows)}
  unchanged_count    : {len(under_indices)}
  compressed_count   : {len(compressed_results)}
  still_over_limit   : {len(still_over)}
  max_tokens_before  : {before_max}
  max_tokens_after   : {after_max}
  출력 파일          : {args.output}
╚══════════════════════════════════════════════════╝""")

    if still_over:
        print("\n[FAIL] 압축 후에도 초과 샘플 존재:")
        for r in still_over:
            print(f"  line {r['line_no']} {r['category']} — {r['after_tokens']} tokens")
        sys.exit(1)
    else:
        print("\n[OK] 모든 샘플이 max_tokens 이하입니다.")

    print("\n카테고리 분포:")
    for k, v in sorted(out_cats.items()):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
