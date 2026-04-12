"""
[R4] LLM 클라이언트 — Ollama + LoRA 어댑터 전환

기능별 파이프라인 섹션 8 참조.
Ollama로 Gemma 4 E2B를 로컬 실행하고, 역할별 LoRA 어댑터를 전환한다.
"""

# TODO: [R4] 구현
# - Ollama API 연동 (generate, chat)
# - 역할별 어댑터 전환 (red/judge/blue)
# - switch_role(), generate() 인터페이스


class AgentShieldLLM:
    """LLM 클라이언트 — 역할별 어댑터 전환"""

    def __init__(self):
        # TODO: [R4] Ollama 연결 초기화
        pass

    def generate(self, prompt: str, role: str = "base", max_tokens: int = 2048) -> str:
        """프롬프트 생성 — role에 따라 어댑터 자동 전환"""
        # TODO: [R4] 구현
        raise NotImplementedError
