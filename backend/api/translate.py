"""Dashboard-only translation helper."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter()


class TranslateRequest(BaseModel):
    text: str = Field(min_length=1, max_length=12000)
    source_language: str = "auto"
    target_language: str = "ko"


class TranslateResponse(BaseModel):
    translated_text: str
    original_text: str
    source_language: str
    target_language: str


def _translate_text(body: TranslateRequest) -> str:
    from deep_translator import GoogleTranslator

    translated = GoogleTranslator(
        source=body.source_language,
        target=body.target_language,
    ).translate(body.text)
    return str(translated or body.text)


@router.post("", response_model=TranslateResponse)
async def translate_text(body: TranslateRequest) -> TranslateResponse:
    try:
        translated = await asyncio.to_thread(_translate_text, body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"번역 실패: {exc}") from exc

    return TranslateResponse(
        translated_text=translated,
        original_text=body.text,
        source_language=body.source_language,
        target_language=body.target_language,
    )
