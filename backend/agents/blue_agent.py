"""
Blue Agent — 방어 코드 생성 프롬프트 빌더 + LLM 응답 파서

Phase 3에서 LLM에 넣을 프롬프트를 만들고, 돌아온 문자열에서 JSON을 꺼낸다.
실제 generate() 호출은 R4 llm_client — 여기서는 문자열만 다룬다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# 방어 코드 작성 가이드 (LLM 시스템/유저 지시에 포함)
# 기획서의 3종 가이드를 요약해 두고, 필요하면 문장만 늘리면 된다.
# ---------------------------------------------------------------------------
DEFENSE_WRITING_GUIDE = """
You must produce exactly three artifacts for this vulnerability:

1) input_filter — Python source for a function:
   def input_filter(text: str) -> dict:
       return {"action": "block"|"warn"|"pass", "reason": str}
   Use re.IGNORECASE; prefer multi-word patterns to reduce false positives.

2) output_filter — Python source for a function:
   def output_filter(text: str) -> str:
       return masked_or_cleaned_text
   Mask emails, phones, API keys (sk-..., AKIA...), SSN-like patterns as [EMAIL], [PHONE], [API_KEY], [SSN].

3) system_prompt_patch — a short string (under 200 chars if possible) appended to the system prompt:
   Category-specific hardening instructions only; do not repeat the whole system prompt.

Output format (strict): a single JSON object with keys:
  "input_filter", "output_filter", "system_prompt_patch"
Values must be strings (Python code as string for the two functions).
Do not wrap in markdown fences. No extra keys. No commentary outside JSON.
"""


# ---------------------------------------------------------------------------
# 프롬프트 빌더
# ---------------------------------------------------------------------------
def build_blue_prompt(
    category: str,
    attack_prompt: str,
    target_response: str,
    *,
    owasp_recommendation: str = "",
    rag_defense_examples: str = "",
) -> str:
    """
    취약점 1건 + (선택) OWASP 한 줄 + (선택) RAG에서 가져온 방어 사례 텍스트 → LLM용 프롬프트.
    """
    owasp_block = (
        f"[OWASP / policy recommendation]\n{owasp_recommendation.strip()}\n\n"
        if owasp_recommendation.strip()
        else ""
    )
    rag_block = (
        f"[Similar defense patterns from knowledge base]\n{rag_defense_examples.strip()}\n\n"
        if rag_defense_examples.strip()
        else ""
    )

    return f"""You are the Blue Agent for an LLM security product. Generate defenses for the finding below.

[Vulnerability]
category: {category}

[Attack prompt]
{attack_prompt}

[Model response that exhibited the issue]
{target_response}

{owasp_block}{rag_block}

[Defense authoring rules]
{DEFENSE_WRITING_GUIDE}
"""


# ---------------------------------------------------------------------------
# 파서 — LLM이 가끔 ```json ... ``` 을 붙이는 경우 대비
# ---------------------------------------------------------------------------
@dataclass
class BlueDefenseBundle:
    """파싱 결과를 다루기 쉬운 객체 (DB에는 JSON 문자열로 저장해도 됨)."""

    input_filter: str
    output_filter: str
    system_prompt_patch: str

    def to_json_str(self) -> str:
        return json.dumps(
            {
                "input_filter": self.input_filter,
                "output_filter": self.output_filter,
                "system_prompt_patch": self.system_prompt_patch,
            },
            ensure_ascii=False,
        )


def parse_blue_response(raw: str) -> BlueDefenseBundle:
    """
    LLM 전체 응답에서 JSON 한 덩어리를 찾아 BlueDefenseBundle로 만든다.
    """
    text = raw.strip()
    # ```json ... ``` 또는 ``` ... ``` 제거
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    else:
        # 첫 {{ ... }} 브레이스 범위 시도
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]

    try:
        data: dict[str, Any] = json.loads(text)
        return BlueDefenseBundle(
            input_filter=str(data["input_filter"]),
            output_filter=str(data["output_filter"]),
            system_prompt_patch=str(data["system_prompt_patch"]),
        )
    except json.JSONDecodeError:
        # LLM이 JSON-ish를 내지만 \s 같은 잘못된 escape로 strict JSON 파싱이 실패할 수 있다.
        # 핵심 3개 필드를 정규식으로 추출해 폴백한다.
        def _extract_field_value(key: str, src: str) -> str | None:
            # JSON string body: (?:\\.|[^"\\])*
            m = re.search(
                rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"',
                src,
                re.DOTALL,
            )
            if not m:
                return None
            value = m.group(1)
            try:
                # JSON 문자열 unescape 시도
                return json.loads(f'"{value}"')
            except Exception:
                # 최소한의 폴백 치환
                return (
                    value.replace('\\"', '"')
                    .replace("\\n", "\n")
                    .replace("\\t", "\t")
                )

        input_filter = _extract_field_value("input_filter", text)
        output_filter = _extract_field_value("output_filter", text)
        system_prompt_patch = _extract_field_value("system_prompt_patch", text)

        if input_filter is None or output_filter is None or system_prompt_patch is None:
            raise

        return BlueDefenseBundle(
            input_filter=input_filter,
            output_filter=output_filter,
            system_prompt_patch=system_prompt_patch,
        )
