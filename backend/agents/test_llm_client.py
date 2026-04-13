import asyncio
import logging
from llm_client import llm_client

# 로깅 설정 (Info 수준으로 출력)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

async def test_agent_switching():
    print("[Ollama 에이전트 스위칭 및 생성 테스트 시작]\n" + "-"*50)

    test_prompt = "너의 역할은 무엇이고, 프롬프트 인젝션 공격에 대해 어떻게 생각하니?"

    # 테스트할 역할 목록
    roles = ["base", "red", "judge", "blue"]

    for role in roles:
        print(f"\n[{role.upper()} AGENT] 호출 중...")
        try:
            # 비동기로 llm_client.generate 호출
            response = await llm_client.generate(
                prompt=test_prompt,
                role=role,
                max_tokens=2048 # 테스트이므로 짧게 응답받음
            )
            print(f"답변:\n{response}\n")
            print("-" * 50)
            
        except Exception as e:
            print(f"[{role.upper()}] 호출 실패: {e}")
            print("-" * 50)

if __name__ == "__main__":
    # 비동기 이벤트 루프 실행
    asyncio.run(test_agent_switching())