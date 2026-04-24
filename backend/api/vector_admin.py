"""[R7] Vector admin API — Chroma attack_results 조회/삭제/재적재."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.auth import UserInfo, get_current_admin
from backend.database import get_db
from backend.models import TestResult
from backend.rag.chromadb_client import add_attack, delete_attack_entries, list_attack_entries

router = APIRouter()


class VectorDeleteRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)
    seed_ids: list[str] = Field(default_factory=list)


class VectorReingestRequest(BaseModel):
    result_ids: list[int] = Field(default_factory=list)
    delete_existing_seed: bool = True


def _vector_row(item: dict) -> dict:
    metadata = item.get("metadata") or {}
    return {
        "id": item.get("id"),
        "seed_id": metadata.get("seed_id"),
        "category": metadata.get("category"),
        "subcategory": metadata.get("subcategory"),
        "source": metadata.get("source"),
        "created_at": metadata.get("created_at"),
        "attack_prompt": item.get("attack_prompt"),
        "target_response": metadata.get("target_response"),
        "session_id": metadata.get("session_id"),
        "result_id": metadata.get("result_id"),
    }


@router.get("/attack-results")
async def list_attack_results(
    limit: int = 20,
    category: Optional[str] = None,
    user: UserInfo = Depends(get_current_admin),
):
    where = {"category": category} if category else None
    rows = list_attack_entries(limit=limit, where=where)
    return {
        "count": len(rows),
        "items": [_vector_row(item) for item in rows],
    }


@router.post("/attack-results/delete")
async def delete_attack_results(
    body: VectorDeleteRequest,
    user: UserInfo = Depends(get_current_admin),
):
    result = delete_attack_entries(ids=body.ids, seed_ids=body.seed_ids)
    return result


@router.post("/attack-results/reingest")
async def reingest_attack_results(
    body: VectorReingestRequest,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    if not body.result_ids:
        raise HTTPException(status_code=400, detail="result_ids가 비어 있습니다")

    rows = (
        await db.execute(
            select(TestResult).where(TestResult.id.in_(body.result_ids)).order_by(TestResult.id.asc())
        )
    ).scalars().all()

    if not rows:
        raise HTTPException(status_code=404, detail="재적재할 결과를 찾을 수 없습니다")

    reingested: list[int] = []
    skipped: list[dict] = []

    for row in rows:
        if not row.attack_prompt or not row.target_response:
            skipped.append({"result_id": row.id, "reason": "empty_attack_or_response"})
            continue

        if body.delete_existing_seed and row.seed_id:
            delete_attack_entries(seed_ids=[row.seed_id])

        saved = add_attack(
            attack_prompt=row.attack_prompt,
            metadata={
                "category": row.category or "unknown",
                "subcategory": row.subcategory or "",
                "target_response": (row.target_response or "")[:1500],
                "source": f"test_result_phase{row.phase}",
                "seed_id": row.seed_id or "",
                "session_id": str(row.session_id) if row.session_id else "",
                "result_id": row.id,
                "judgment": row.judgment,
                "severity": row.severity or "",
            },
        )
        if saved:
            reingested.append(row.id)
        else:
            skipped.append({"result_id": row.id, "reason": "duplicate_or_store_failed"})

    return {
        "requested": body.result_ids,
        "reingested": reingested,
        "skipped": skipped,
    }