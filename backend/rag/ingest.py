"""
[R4] 데이터 적재 — ChromaDB에 방어 패턴/공격 데이터 적재

세부기획서 섹션 2-2 참조.
defense_patterns: ~100건 수동 수집
attack_results: Phase 2에서 자동 축적
"""

# TODO: [R4] 방어 패턴 적재 (R2: 공격 데이터 적재 부분도 이 파일 사용)

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)
import asyncio
import asyncpg
import json
import uuid
from backend.rag.chromadb_client import rag_client
from backend.config import settings

DEFENSE_DATA_DIR = os.path.join(project_root, "data", "defense_patterns")
ATTACK_DATA_DIR = os.path.join(project_root, "data", "attack_patterns")

# 방어 패턴 chromadb 적재 함수 - 최종 출력에 따라 수정 필요
def ingest_defense_patterns():
    print("\n방어 패턴 ChromaDB 적재 시작\n")
    if not os.path.exists(DEFENSE_DATA_DIR):
        print(f"방어 패턴 데이터 디렉토리 '{DEFENSE_DATA_DIR}'가 존재하지 않습니다.")
        return
    
    patterns = []
    for filename in os.listdir(DEFENSE_DATA_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(DEFENSE_DATA_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        patterns.extend(data)
                    else:
                        patterns.append(data)
                except Exception as e:
                    print(f"{filename} 읽기 오류: {e}")
        
    if not patterns:
        print("적재할 방어 패턴 데이터가 없습니다.")
        return
    
    ids, documents, metadatas = [], [], []
    for item in patterns:
        doc_id = item.get("id", str(uuid.uuid4()))
        ids.append(doc_id)

        category = item.get("category", "Unknown")
        title = item.get("title", "defense pattern")
        explanation = item.get("explanation", "")

        documents.append(f"[{category}] {title}: {explanation}")
        metadatas.append({
            "category": category,
            "title": title,
            "defense_code": item.get("defense_code", ""),
            "source": item.get("source", "custom")
        })

    try:
        rag_client.defense_col.upsert(ids=ids, documents=documents, metadatas=metadatas)
        print(f"{len(patterns)}건의 방어 패턴 적재 완료 (ChromaDB)")
    except Exception as e:
        print(f"ChromaDB 적재 오류: {e}")

# 공격 패턴 적재 함수 - 최종 출력에 따라 수정 필요, 테이블 스키마 있을 시 그에 맞게 조정 필요
async def ingest_attack_patterns():
    print("\n공격 패턴 PostgreSQL 적재 시작\n")
    if not os.path.exists(ATTACK_DATA_DIR):
        print(f"데이터 폴더가 없습니다: {ATTACK_DATA_DIR}")
        return
    
    attacks = []
    for filename in os.listdir(ATTACK_DATA_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(ATTACK_DATA_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            attacks.append(json.loads(line))
                        except Exception as e:
                            print(f"JSON 파싱 오류: {e}")

    if not attacks:
        print("적재할 공격 패턴 데이터가 없습니다.")
        return
    
    # DB 연결
    db_url = settings.DATABASE_URL.replace("+asyncpg", "")
    # 테이블 맞게 수정
    for attempt in range(1, 6):
        try:
            print(f"DB 연결 시도 중... ({attempt}/5)")
            conn = await asyncpg.connect(db_url, timeout=10)

            # 테이블 초기화 및 생성
            await conn.execute("DROP TABLE IF EXISTS attack_patterns CASCADE;")
            await conn.execute("""
                CREATE TABLE attack_patterns (
                    id SERIAL PRIMARY KEY,
                    prompt_text TEXT NOT NULL,
                    category VARCHAR(10) NOT NULL,
                    subcategory VARCHAR(50),
                    severity VARCHAR(10) DEFAULT 'Medium',
                    source VARCHAR(50),
                    language VARCHAR(10) DEFAULT 'en',
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)

            records = [
            (
                item.get("prompt_text"),
                item.get("category", "Unknown")[:10],
                item.get("subcategory"),
                item.get("severity", "Medium")[:10],
                item.get("source", "unknown")[:50],
                item.get("language", "en")[:10]
            )
            for item in attacks
            ]

            await conn.executemany("""
                INSERT INTO attack_patterns (prompt_text, category, subcategory, severity, source, language)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, records)

            print(f"{len(attacks)}건의 공격 패턴 적재 성공!")
            await conn.close()
            break

        except (asyncpg.PostgresError, OSError) as e:
            print(f"연결 실패: {e}. 3초 후 다시 시도합니다")
            await asyncio.sleep(3)

    else:
        print("결국 PostgreSQL 연결에 실패했습니다. DB 상태를 확인하세요.")

# 실행 엔드리 포인드
async def main():
    print("=" * 50)
    print("AgentShield 통합 데이터 적재 파이프라인 시작")
    print("=" * 50)

    # 방어 패턴 적재 (동기 실행)
    ingest_defense_patterns()

    # 공격 패턴 적재 (비동기 실행)
    await ingest_attack_patterns()

    print("\n모든 데이터 적재가 완료되었습니다!")

if __name__ == "__main__":
    asyncio.run(main())