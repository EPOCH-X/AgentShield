from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RedRewardInput:
    attack_prompt: str
    target_response: str
    category: str = "LLM01"
    round: int = 0
    seed_id: str = ""
    judge: dict[str, Any] = field(default_factory=dict)
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RedRewardResult:
    score: float
    raw_score: int
    positives: list[str]
    negatives: list[str]
    training_eligible: bool
    exploit_value: str
