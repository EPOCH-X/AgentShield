import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import asyncio
import asyncpg
from backend.rag.chromadb_client import rag_client
from backend.config import settings

async def verify_databases():
    print("\n[검증] PostgreSQL 및 ChromaDB 연결 테스트\n")

    try:
        # DB에 몇 개가 들어있는지 카운트
        count = rag_client.defense_col.count()
        print(f"현재 저장된 방어 패턴 수: {count}개")

        # 'ignore' 라는 키워드로 AI 유사도 검색 테스트
        print("\n[AI 유사도 검색 테스트 - 검색어: 'ignore 키워드 차단']")
        results = rag_client.search_defense("ignore 키워드 차단", n_results=1)
        
        if results['documents'] and len(results['documents'][0]) > 0:
            distance = results['distances'][0][0]
            similarity = 1 - distance
            print(f"찾은 문서: {results['documents'][0][0]}")
            print(f"메타데이터(원본): {results['metadatas'][0][0]}")
            print(f"유사도 거리: {similarity:.4f} (1에 가까울수록 유사함)")
    except Exception as e:
        print(f"ChromaDB 에러: {e}")

    try:
        db_url = settings.DATABASE_URL.replace("+asyncpg", "")
        conn = await asyncpg.connect(db_url)
        
        # 테이블 데이터 카운트
        count = await conn.fetchval("SELECT COUNT(*) FROM attack_patterns")
        print(f"현재 저장된 공격 패턴 수: {count}개")
        
        # 방금 넣은 데이터 하나 꺼내보기
        row = await conn.fetchrow("SELECT prompt_text, category FROM attack_patterns LIMIT 1")
        if row:
            print(f"샘플 조회: [{row['category']}] {row['prompt_text']}")
            
    except Exception as e:
        print(f"PostgreSQL 에러: {e}\n(혹시 테이블 생성이 안 되었다면, 아직 R7의 init_db 로직이 실행 안 된 것입니다!)")
    finally:
        if 'conn' in locals():
            await conn.close()

if __name__ == "__main__":
    asyncio.run(verify_databases())