"""
Blue Agent — 방어 응답/코드 생성 프롬프트 빌더 + LLM 응답 파서

Phase 3에서 LLM에 넣을 프롬프트를 만들고, 돌아온 문자열에서 JSON을 꺼낸다.
실제 generate() 호출은 R4 llm_client — 여기서는 문자열만 다룬다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from backend.core.mitre_mapping import get_mitre_mapping

# ---------------------------------------------------------------------------
# 방어 응답/코드 작성 가이드 (LLM 시스템/유저 지시에 포함)
# 기획서의 3종 가이드를 요약해 두고, 필요하면 문장만 늘리면 된다.
# ---------------------------------------------------------------------------
DEFENSE_WRITING_GUIDE = """
Generate ONLY the defenses that are necessary for this vulnerability.
If an artifact is not needed, return an empty string "" for that field.

Artifacts:

0) defended_response — the primary output for this vulnerability.
   Return a concise safer response text the chatbot should output to this exact attack prompt.
   Keep it policy-aligned, avoid leaking secrets/system prompt/tool internals, and preserve helpfulness when possible.

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
   If policy patching is unnecessary, return "".

Output format (strict): a single JSON object with keys:
  "defended_response", "input_filter", "output_filter", "system_prompt_patch", "defense_rationale"
Values must be strings (Python code as string for the two functions).
defense_rationale must explain in 1-3 sentences why each artifact is present or empty.
Do not wrap in markdown fences. No extra keys. No labels. No commentary outside JSON.
Return EXACTLY one JSON object and nothing else.
The final response MUST start with "{" and end with "}".
If your output is not valid JSON parseable by json.loads, it is considered a failed response.

Mandatory self-check (exactly one internal pass before final output):
1) Ensure json.loads(your_output) succeeds.
2) Ensure all required keys exist and only these keys are present.
3) Ensure all values are strings.
4) Remove any extra text, labels, markdown fences, or examples.
If any check fails, rewrite once and output only the corrected JSON object.

Input-filter precision constraints:
- Do NOT block on a single generic keyword alone (e.g., "ignore", "override", "tool call").
- Prefer conjunction-style rules that combine action + protected target
  (e.g., "ignore" + "instruction|rule|system|policy").
- Prefer regex patterns with context boundaries over broad substring checks.
"""


def _category_policy_block(category: str) -> str:
    """카테고리별 동적 정책 블록(유저 프롬프트에 삽입)."""
    c = (category or "").strip().upper()
    common = (
        "- Objective: block/mitigate this case with minimal false positives.\n"
        "- Prefer precise structural patterns over broad single-keyword rules.\n"
        "- If an artifact is empty, explain why in defense_rationale."
    )

    if c == "LLM01":
        specific = (
            "- Focus on instruction-boundary attacks (override/ignore/hidden directives).\n"
            "- Do NOT block on standalone 'ignore'; require action+target context "
            "(e.g., 'ignore' with 'previous instructions|system rules|policy').\n"
            "- Prioritize patterns like 'ignore previous instructions', 'override safety policy', hidden control sections.\n"
            "- Strengthen system_prompt_patch to preserve system rules over user-supplied override text."
        )
    elif c == "LLM02":
        specific = (
            "- Focus on sensitive-data disclosure/extraction requests.\n"
            "- Prioritize masking for API keys, bearer tokens, emails, phone numbers, account identifiers.\n"
            "- Prefer output_filter redaction first; use input_filter blocking for explicit extraction prompts."
        )
    elif c == "LLM06":
        specific = (
            "- Focus on excessive agency and unauthorized tool execution.\n"
            "- Prioritize structured signatures (<tool_call>, tool_call(...), function_call payloads).\n"
            "- Do NOT use standalone broad patterns like 'tool call' without execution context."
        )
    elif c == "LLM07":
        specific = (
            "- Focus on system prompt/policy leakage and hidden-instruction disclosure.\n"
            "- Prioritize patterns requesting internal instructions, role/system prompt reveal, encoded leakage attempts.\n"
            "- Strengthen system_prompt_patch to refuse disclosure of internal rules/configuration."
        )
    else:
        specific = "- Apply generic defense hardening aligned to OWASP category signals in the case context."

    return (
        "[Dynamic category policy]\n"
        f"category: {c or 'UNKNOWN'}\n"
        f"{common}\n"
        f"{specific}\n"
    )


# ---------------------------------------------------------------------------
# 프롬프트 빌더
# ---------------------------------------------------------------------------
def build_blue_prompt(
    category: str,
    attack_prompt: str,
    target_response: str,
    *,
    failure_mode: str | None = None,
    mitre_technique_id: str | None = None,
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
    mitre_block = ""
    if failure_mode or mitre_technique_id:
        mapping = get_mitre_mapping(category, failure_mode)
        primary = mapping.get("primary", {})
        mapped_id = str(primary.get("technique_id", ""))
        display_id = mitre_technique_id or mapped_id
        technique_name = str(primary.get("name", "Unknown Technique"))
        tactic = str(primary.get("tactic", "Unknown Tactic"))
        ref_url = str(primary.get("url", ""))
        mode_line = f"- Failure mode: {failure_mode}\n" if failure_mode else ""
        mismatch_line = ""
        if mitre_technique_id and mapped_id and mitre_technique_id != mapped_id:
            mismatch_line = f"- Category mapping default: {mapped_id}\n"
        mitre_block = (
            "[MITRE ATT&CK context]\n"
            f"- Technique: {display_id} — {technique_name}\n"
            f"- Tactic: {tactic}\n"
            f"- Reference: {ref_url}\n"
            f"{mode_line}"
            f"{mismatch_line}"
            "- Reflect this ATT&CK technique's mitigation strategy in the defense artifacts.\n\n"
        )
    category_policy_block = _category_policy_block(category)

    return f"""You are the Blue Agent for an LLM security product. Generate defenses for the finding below.

[Vulnerability]
category: {category}

[Attack prompt]
{attack_prompt}

[Model response that exhibited the issue]
{target_response}

{owasp_block}{rag_block}{mitre_block}
{category_policy_block}

[Defense authoring rules]
{DEFENSE_WRITING_GUIDE}
"""


# ---------------------------------------------------------------------------
# 파서 — LLM이 가끔 ```json ... ``` 을 붙이는 경우 대비
# ---------------------------------------------------------------------------
@dataclass
class BlueDefenseBundle:
    """파싱 결과를 다루기 쉬운 객체 (DB에는 JSON 문자열로 저장해도 됨)."""

    defended_response: str
    input_filter: str
    output_filter: str
    system_prompt_patch: str
    defense_rationale: str

    def to_json_str(self) -> str:
        return json.dumps(
            {
                "defended_response": self.defended_response,
                "input_filter": self.input_filter,
                "output_filter": self.output_filter,
                "system_prompt_patch": self.system_prompt_patch,
                "defense_rationale": self.defense_rationale,
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
            defended_response=str(data.get("defended_response", "")),
            input_filter=str(data.get("input_filter", "")),
            output_filter=str(data.get("output_filter", "")),
            system_prompt_patch=str(data.get("system_prompt_patch", "")),
            defense_rationale=str(data.get("defense_rationale", "")),
        )
    except json.JSONDecodeError:
        # LLM이 JSON-ish를 내지만 \s 같은 잘못된 escape로 strict JSON 파싱이 실패할 수 있다.
        # 핵심 필드를 정규식으로 추출해 폴백한다.
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

        defended_response = _extract_field_value("defended_response", text)
        input_filter = _extract_field_value("input_filter", text)
        output_filter = _extract_field_value("output_filter", text)
        system_prompt_patch = _extract_field_value("system_prompt_patch", text)
        defense_rationale = _extract_field_value("defense_rationale", text)

        if (
            defended_response is None
            or input_filter is None
            or output_filter is None
            or system_prompt_patch is None
        ):
            raise

        return BlueDefenseBundle(
            defended_response=defended_response,
            input_filter=input_filter,
            output_filter=output_filter,
            system_prompt_patch=system_prompt_patch,
            defense_rationale=defense_rationale or "",
        )
