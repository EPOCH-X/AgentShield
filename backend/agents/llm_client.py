"""
[R4] LLM 클라이언트 — Ollama + LoRA 어댑터 전환

기능별 파이프라인 섹션 8 참조.
Ollama로 Gemma 4 E2B를 로컬 실행하고, 역할별 LoRA 어댑터를 전환한다.
"""

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import httpx
import logging
from backend.config import settings
from backend.agents.red_agent import RED_AGENT_SYSTEM_PROMPT

# TODO: [R4] 구현
# - Ollama API 연동 (generate, chat)
# - 역할별 어댑터 전환 (red/judge/blue)
# - switch_role(), generate() 인터페이스

logger = logging.getLogger(__name__)

class AgentShieldLLM:
    """
    R1의 LangGraph에서 호출할 비동기 LLM 클라이언트.
    요청된 role에 따라 Ollama에 로드된 에이전트를 스위칭하여 호출합니다.
    """
    def __init__(self, host: str = settings.OLLAMA_BASE_URL):
        self.api_url = f"{host}/api/chat"

    @staticmethod
    def _resolve_model_name(role: str) -> str:
        role_models = {
            "base": settings.OLLAMA_MODEL,
            "red": settings.OLLAMA_RED_MODEL,
            "judge": settings.OLLAMA_JUDGE_MODEL,
            "blue": settings.OLLAMA_BLUE_MODEL,
        }
        return role_models.get(role, f"agent-{role}")

    @staticmethod
    def _build_messages(prompt: str, role: str) -> list[dict[str, str]]:
        if role == "red":
            return [
                {"role": "system", "content": RED_AGENT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]

        return [{"role": "user", "content": prompt}]

    @staticmethod
    def _resolve_max_tokens(role: str, max_tokens: int | None) -> int:
        if max_tokens is not None:
            return max_tokens
        if role == "red":
            return settings.RED_AGENT_NUM_PREDICT
        return settings.LLM_DEFAULT_NUM_PREDICT

    async def generate(self, prompt: str, role: str = "base", max_tokens: int | None = None) -> str:
        model_name = self._resolve_model_name(role)
        resolved_max_tokens = self._resolve_max_tokens(role, max_tokens)

        # Judge는 엄격하게(0.1), 생성 에이전트들은 약간의 창의성 허용(0.6)
        temperature = 0.1 if role == "judge" else 0.6

        payload = {
            "model": model_name,
            "messages": self._build_messages(prompt, role),
            "stream": False,
            "think": False,
            "options": {
                "num_predict": resolved_max_tokens,
                "temperature": temperature
            }
        }

        async with httpx.AsyncClient(timeout=settings.LLM_REQUEST_TIMEOUT) as client:
            try:
                response = await client.post(self.api_url, json=payload)

                # 어댑터(모델)가 아직 등록되지 않은 경우 (404 에러 시 폴백)
                if response.status_code == 404 and role != "base":
                    logger.warning(f"'{model_name}' 모델이 없습니다. 기본 '{settings.OLLAMA_MODEL}'로 폴백하여 진행합니다.")
                    return await self.generate(prompt, role="base", max_tokens=resolved_max_tokens)
                
                response.raise_for_status()
                result = response.json()
                
                print(f"\n[RAW OLLAMA 응답 - {model_name}]: {result}\n")

                return result.get("message", {}).get("content", "").strip()

            except httpx.HTTPError as e:
                logger.error(f"Ollama 통신 오류 [{model_name}]: {e}")
                raise Exception(f"LLM 생성 실패 ({model_name}): {e}")
            
# 외부에서 싱글톤처럼 재사용할 수 있도록 인스턴스화
llm_client = AgentShieldLLM()