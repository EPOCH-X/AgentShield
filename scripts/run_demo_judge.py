#!/usr/bin/env python3
"""Run the demo Judge path from the dashboard API."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.core.judge import full_judge  # noqa: E402


async def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        category = str(payload.get("category") or "LLM02")
        attack_prompt = str(payload.get("attack_prompt") or "")
        target_response = str(payload.get("target_response") or "")
        if not attack_prompt.strip() or not target_response.strip():
            raise ValueError("attack_prompt and target_response are required")

        result = await full_judge(category, attack_prompt, target_response)
        print(json.dumps({"ok": True, "judge": result}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
