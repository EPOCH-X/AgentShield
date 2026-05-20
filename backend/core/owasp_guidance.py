"""
OWASP LLM Top 10 권고 가이드 로더.

[정책]
- 카테고리별 권고는 보안팀이 관리하는 `data/owasp_guidance.yaml` 한 곳에서만 정의한다.
- phase5_policy_export, /api/v1/policy-export 등 모든 권고 표시는 이 모듈을 통해 가져간다.
- 코드에 카테고리→action 매핑이 하드코딩되지 않게 한다.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml


_GUIDANCE_PATH = Path(__file__).resolve().parents[2] / "data" / "owasp_guidance.yaml"


@lru_cache(maxsize=1)
def load_guidance() -> dict[str, Any]:
    """yaml 파일을 한 번만 읽어 캐시. 파일이 없으면 빈 dict 반환."""
    if not _GUIDANCE_PATH.exists():
        return {"version": 0, "source": "", "categories": {}}
    with _GUIDANCE_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "categories" not in data or not isinstance(data["categories"], dict):
        data["categories"] = {}
    return data


def get_source() -> str:
    return str(load_guidance().get("source") or "")


def get_category(category: Optional[str]) -> Optional[dict[str, Any]]:
    if not category:
        return None
    return load_guidance().get("categories", {}).get(category.upper())


def all_categories() -> dict[str, dict[str, Any]]:
    return dict(load_guidance().get("categories", {}))


def default_action(category: Optional[str], fallback: str = "refuse") -> str:
    entry = get_category(category)
    if not entry:
        return fallback
    return str(entry.get("default_action") or fallback)


def fix_targets(category: Optional[str]) -> list[str]:
    entry = get_category(category)
    if not entry:
        return []
    return [str(item) for item in (entry.get("fix_targets") or [])]


def must_not_contain(category: Optional[str]) -> list[str]:
    entry = get_category(category)
    if not entry:
        return []
    return [str(item) for item in (entry.get("must_not_contain") or [])]


def build_category_action_map(categories_present: set) -> dict[str, str]:
    """이번 스캔에 등장한 카테고리만 추려서 매핑 반환."""
    result: dict[str, str] = {}
    for cat in sorted(categories_present):
        if not cat:
            continue
        action = default_action(cat)
        result[cat] = action
    return result


def build_input_output_policy(categories_present: set) -> tuple[dict[str, bool], dict[str, bool]]:
    """각 카테고리의 input/output_policy_flag를 모아서 boolean 매핑 생성."""
    input_policy: dict[str, bool] = {}
    output_policy: dict[str, bool] = {}
    for cat, entry in all_categories().items():
        in_flag = entry.get("input_policy_flag")
        out_flag = entry.get("output_policy_flag")
        present = cat in categories_present
        if in_flag:
            input_policy[str(in_flag)] = present
        if out_flag:
            output_policy[str(out_flag)] = present
    # 외부 공유 산출물에서는 항상 마스킹 룰을 적용한다는 기본값 유지
    output_policy.setdefault("mask_sensitive_values", True)
    return input_policy, output_policy
