#!/usr/bin/env python3
"""Run Blue Agent defense generation and Judge verification for demo UI."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.agents.blue_agent import build_blue_prompt, parse_blue_response  # noqa: E402
from backend.agents.llm_client import AgentShieldLLM  # noqa: E402
from backend.core.judge import full_judge  # noqa: E402


async def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        category = str(payload.get("category") or "LLM02")
        attack_prompt = str(payload.get("attack_prompt") or "")
        target_response = str(payload.get("target_response") or "")
        if not attack_prompt.strip() or not target_response.strip():
            raise ValueError("attack_prompt and target_response are required")

        attack_judge = await full_judge(category, attack_prompt, target_response)

        blue_prompt = build_blue_prompt(
            category=category,
            attack_prompt=attack_prompt,
            target_response=target_response,
            judge_detail=str(attack_judge.get("detail") or ""),
        )
        llm = AgentShieldLLM()
        raw_blue = await llm.generate(blue_prompt, role="blue", max_tokens=900)
        raw_blue_text = str(raw_blue or "").strip()
        if raw_blue_text.startswith("[Error]"):
            raise RuntimeError(raw_blue_text)

        bundle = parse_blue_response(raw_blue_text)
        defended_response = bundle.defended_response.strip()
        if not defended_response:
            raise RuntimeError("Blue Agent returned an empty defended_response")

        defense_judge = await full_judge(category, attack_prompt, defended_response)
        print(
            json.dumps(
                {
                    "ok": True,
                    "defended_response": defended_response,
                    "defense_rationale": bundle.defense_rationale,
                    "attack_judge": attack_judge,
                    "defense_judge": defense_judge,
                    "raw_blue": raw_blue_text,
                },
                ensure_ascii=False,
            )
        )
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
