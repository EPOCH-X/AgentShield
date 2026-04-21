"""
DPO 데이터 내보내기 유틸리티

동일 seed_id 기준으로 vulnerable(chosen) / safe(rejected) 쌍을 매칭하여
trl DPOTrainer 호환 JSONL을 생성한다.

데이터 소스:
  --source db   : PostgreSQL test_results 테이블 (async)
  --source json : results/*.json 파일

사용법:
  python -m backend.finetuning.export_dpo_data --source json --file results/pipeline_20260416_145238.json
  python -m backend.finetuning.export_dpo_data --source db --session latest
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "finetuning"


def _build_dpo_pairs_from_records(records: list[dict]) -> list[dict]:
    """seed_id 기준으로 DPO (chosen/rejected) 쌍을 생성한다.

    규칙:
    - 같은 seed_id에 vulnerable + safe 결과가 모두 있어야 쌍 생성 가능
    - chosen = vulnerable 공격 프롬프트 (Red Agent가 성공한 변형)
    - rejected = safe 공격 프롬프트 (방어에 막힌 원본/변형)
    - 여러 쌍이 가능하면 모두 생성 (N:M 조합)
    """
    by_seed: dict[str, dict[str, list]] = defaultdict(lambda: {"vulnerable": [], "safe": []})

    for r in records:
        seed_id = r.get("seed_id", "")
        if not seed_id:
            continue
        judgment = r.get("judgment", "")
        if judgment == "vulnerable":
            by_seed[seed_id]["vulnerable"].append(r)
        elif judgment == "safe":
            by_seed[seed_id]["safe"].append(r)

    pairs = []
    for seed_id, groups in by_seed.items():
        vulns = groups["vulnerable"]
        safes = groups["safe"]
        if not vulns or not safes:
            continue

        for v in vulns:
            # 각 vulnerable에 대해 safe 1건만 매칭 (랜덤 선택으로 다양성 확보)
            s = random.choice(safes)
            prompt = (
                f"You are a Red Team AI. Generate an attack prompt for category "
                f"{v.get('category', '?')} that bypasses the target LLM's safety."
            )
            pairs.append({
                "prompt": prompt,
                "chosen": v.get("mutated_prompt") or v.get("attack_prompt", ""),
                "rejected": s.get("mutated_prompt") or s.get("attack_prompt", ""),
                "seed_id": seed_id,
                "category": v.get("category", ""),
            })

    return pairs


def _load_records_from_json(file_path: Path) -> list[dict]:
    """pipeline JSON 파일에서 Phase 1 + Phase 2 결과를 레코드로 변환한다."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []

    # Phase 1 vulnerable
    for attack in data.get("Phase1", {}).get("vulnerable", []):
        records.append({
            "seed_id": attack.get("seed_id", ""),
            "phase": 1,
            "category": attack.get("category", ""),
            "subcategory": attack.get("subcategory", ""),
            "attack_prompt": attack.get("attack_prompt", ""),
            "target_response": attack.get("target_response", ""),
            "judgment": attack.get("judgment", "vulnerable"),
        })

    # Phase 2 results
    for result in data.get("Phase2_Red_Agent", {}).get("results", []):
        records.append({
            "seed_id": result.get("seed_id", ""),
            "phase": 2,
            "category": result.get("category", ""),
            "subcategory": result.get("subcategory", ""),
            "attack_prompt": result.get("original_prompt", ""),
            "mutated_prompt": result.get("mutated_prompt", ""),
            "target_response": result.get("target_response", ""),
            "judgment": result.get("judgment", ""),
            "round": result.get("round"),
        })

    return records


async def _load_records_from_db(session_filter: str = "latest") -> list[dict]:
    """PostgreSQL에서 test_results를 로드한다."""
    from sqlalchemy import select, desc
    from backend.database import async_session
    from backend.models.test_result import TestResult
    from backend.models.test_session import TestSession

    async with async_session() as db:
        # 세션 선택
        if session_filter == "latest":
            stmt = select(TestSession).order_by(desc(TestSession.created_at)).limit(1)
            result = await db.execute(stmt)
            session = result.scalar_one_or_none()
            if not session:
                logger.warning("DB에 세션이 없습니다.")
                return []
            session_id = session.id
        else:
            session_id = session_filter

        # 결과 로드
        stmt = select(TestResult).where(TestResult.session_id == session_id)
        result = await db.execute(stmt)
        rows = result.scalars().all()

    records = []
    for r in rows:
        records.append({
            "seed_id": r.seed_id or "",
            "phase": r.phase,
            "category": r.category or "",
            "subcategory": r.subcategory or "",
            "attack_prompt": r.attack_prompt or "",
            "target_response": r.target_response or "",
            "judgment": r.judgment or "",
            "round": r.round,
            "detail": r.detail or "",
        })

    return records


def _write_jsonl(pairs: list[dict], train_path: Path, test_path: Path, test_ratio: float = 0.1):
    """DPO 쌍을 train/test JSONL로 분할 저장한다."""
    random.shuffle(pairs)
    split = max(1, int(len(pairs) * test_ratio))
    test_pairs = pairs[:split]
    train_pairs = pairs[split:]

    train_path.parent.mkdir(parents=True, exist_ok=True)

    for path, data in [(train_path, train_pairs), (test_path, test_pairs)]:
        with open(path, "w", encoding="utf-8") as f:
            for item in data:
                # trl DPOTrainer 포맷: prompt, chosen, rejected
                row = {
                    "prompt": item["prompt"],
                    "chosen": item["chosen"],
                    "rejected": item["rejected"],
                }
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"  저장: {path} ({len(data)}건)")


async def export_dpo(source: str, session: str = "latest", file: str = None):
    """DPO 데이터 내보내기 메인 로직."""
    if source == "json":
        if not file:
            # 최신 파일 자동 선택
            results_dir = Path(__file__).resolve().parent.parent.parent / "results"
            json_files = sorted(results_dir.glob("pipeline_*.json"))
            if not json_files:
                print("  ❌ results/ 디렉토리에 파이프라인 결과 파일이 없습니다.")
                return
            file = str(json_files[-1])
            print(f"  최신 결과 파일 사용: {file}")

        records = _load_records_from_json(Path(file))
    elif source == "db":
        records = await _load_records_from_db(session)
    else:
        print(f"  ❌ 지원하지 않는 소스: {source}")
        return

    print(f"  레코드 로드: {len(records)}건")

    pairs = _build_dpo_pairs_from_records(records)
    print(f"  DPO 쌍 생성: {len(pairs)}건")

    if not pairs:
        print("  ⚠ DPO 쌍을 생성할 수 없습니다 (같은 seed_id에 vulnerable+safe 모두 필요)")
        return

    # 카테고리별 통계
    cat_counts = defaultdict(int)
    for p in pairs:
        cat_counts[p["category"]] += 1
    for cat, cnt in sorted(cat_counts.items()):
        print(f"    {cat}: {cnt}쌍")

    train_path = OUTPUT_DIR / "dpo_red_train.jsonl"
    test_path = OUTPUT_DIR / "dpo_red_test.jsonl"
    _write_jsonl(pairs, train_path, test_path)

    print(f"\n  ✅ DPO 데이터 내보내기 완료")


def main():
    parser = argparse.ArgumentParser(
        description="DPO 데이터 내보내기 (seed_id 기준 chosen/rejected 쌍)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""예시:
  python -m backend.finetuning.export_dpo_data --source json
  python -m backend.finetuning.export_dpo_data --source json --file results/pipeline_20260416_145238.json
    python -m backend.finetuning.export_dpo_data --source db --session latest
""",
    )
    parser.add_argument("--source", choices=["db", "json"], default="json", help="데이터 소스 (기본: json)")
    parser.add_argument("--session", default="latest", help="DB 세션 필터 (기본: latest)")
    parser.add_argument("--file", default=None, help="JSON 파일 경로")
    args = parser.parse_args()

    asyncio.run(export_dpo(args.source, args.session, args.file))


if __name__ == "__main__":
    main()
