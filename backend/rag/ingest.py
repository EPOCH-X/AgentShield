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

def smart_json_loader(filepath):
    """표준 JSON 배열([])과 줄바꿈 JSON(JSONL)을 모두 처리합니다."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            
            # 파일 전체가 하나의 JSON 리스트인 경우 (보여주신 데이터 형식)
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    return data
                return [data]
            except json.JSONDecodeError:
                # 방법 2: 줄바꿈마다 JSON이 있는 경우 (JSONL)
                data_list = []
                for line in content.splitlines():
                    if line.strip():
                        try:
                            data_list.append(json.loads(line))
                        except:
                            continue
                return data_list
    except Exception as e:
        print(f"파일 읽기 오류 ({os.path.basename(filepath)}): {e}")
        return []

# 방어 패턴 chromadb 적재 함수 - 최종 출력에 따라 수정 필요
def ingest_defense_patterns():
    print("\n방어 패턴 ChromaDB 적재 시작\n")
    if not os.path.exists(DEFENSE_DATA_DIR):
        print(f"방어 패턴 데이터 디렉토리 '{DEFENSE_DATA_DIR}'가 존재하지 않습니다.")
        return
    
    all_patterns = []
    for filename in os.listdir(DEFENSE_DATA_DIR):
        if filename.endswith((".json", ".jsonl")):
            filepath = os.path.join(DEFENSE_DATA_DIR, filename)
            all_patterns.extend(smart_json_loader(filepath))
        
    if not all_patterns:
        print("적재할 방어 패턴 데이터가 없습니다.")
        return
    
    ids, docs, metas = [], [], []
    id_counts: dict[str, int] = {}
    for item in all_patterns:
        base_id = str(item.get("id", uuid.uuid4()))
        seen = id_counts.get(base_id, 0)
        id_counts[base_id] = seen + 1
        # Chroma upsert는 한 배치 내 중복 ID를 허용하지 않으므로 suffix를 붙여 유니크 보장.
        chroma_id = base_id if seen == 0 else f"{base_id}__dup{seen}"
        category = str(item.get("category", "Unknown"))
        title = str(item.get("title", "No Title"))
        source = str(item.get("source", "custom"))
        attack_prompt = str(item.get("attack_prompt") or "")
        target_response = str(item.get("target_response") or "")
        defended_response = str(item.get("defended_response") or "")
        defense_rationale = str(item.get("defense_rationale") or "")
        judge_reason = str(item.get("judge_reason") or "")
        failure_mode = str(item.get("failure_mode") or "")
        verify_result = str(item.get("verify_result") or "")

        # defense_code 내부 JSON에도 핵심 필드가 있을 수 있어 보강한다.
        defense_code = item.get("defense_code", "")
        if isinstance(defense_code, str) and defense_code.strip().startswith("{"):
            try:
                parsed_code = json.loads(defense_code)
                if not defended_response:
                    defended_response = str(parsed_code.get("defended_response") or "")
                if not defense_rationale:
                    defense_rationale = str(parsed_code.get("defense_rationale") or "")
            except Exception:
                pass

        document = (
            f"[{category}] "
            f"title={title}; "
            f"failure_mode={failure_mode}; "
            f"verify_result={verify_result}; "
            f"attack={attack_prompt[:220]}; "
            f"target={target_response[:220]}; "
            f"defended_response={defended_response[:260]}; "
            f"rationale={defense_rationale[:220]}; "
            f"judge_reason={judge_reason[:180]}"
        )
        ids.append(chroma_id)
        docs.append(document)
        metas.append({
            "source_id": base_id,
            "category": category,
            "title": title,
            "source": source,
            "verify_result": verify_result,
            "failure_mode": failure_mode,
            "attack_prompt": attack_prompt,
            "target_response": target_response,
            "defended_response": defended_response,
            "defense_rationale": defense_rationale,
            "judge_reason": judge_reason,
            "defense_code": defense_code,
        })

    try:
        rag_client.defense_col.upsert(ids=ids, documents=docs, metadatas=metas)
        print(f"{len(all_patterns)}건의 방어 패턴 적재 완료")
    except Exception as e:
        print(f"ChromaDB 적재 실패: {e}")

# 공격 패턴 적재 함수 - 최종 출력에 따라 수정 필요
async def ingest_attack_patterns():
    print("\n공격 패턴 PostgreSQL 적재 시작\n")
    if not os.path.exists(ATTACK_DATA_DIR):
        print(f"데이터 폴더가 없습니다: {ATTACK_DATA_DIR}")
        return
    
    all_attacks = []
    for filename in os.listdir(ATTACK_DATA_DIR):
        if filename.endswith((".json", ".jsonl")):
            filepath = os.path.join(ATTACK_DATA_DIR, filename)
            all_attacks.extend(smart_json_loader(filepath))

    if not all_attacks:
        print("적재할 공격 패턴 데이터가 없습니다.")
        return
    
    # DB 연결
    # 테이블 맞게 수정
    db_url = settings.DATABASE_URL.replace("+asyncpg", "")
    try:
        conn = await asyncpg.connect(db_url)
        
        await conn.execute("DROP TABLE IF EXISTS attack_patterns CASCADE;")
        await conn.execute("""
            CREATE TABLE attack_patterns (
                id SERIAL PRIMARY KEY,
                prompt_text TEXT NOT NULL,
                intention TEXT,
                category VARCHAR(10) NOT NULL,
                subcategory VARCHAR(50),
                severity VARCHAR(10) DEFAULT 'Medium'
            )
        """)

        records = [
            (
                a.get("prompt_text", ""),
                a.get("intention"),
                a.get("category", "Unknown")[:10],
                a.get("subcategory"),
                a.get("severity", "Medium")[:10],
            ) for a in all_attacks
        ]

        await conn.executemany("""
            INSERT INTO attack_patterns (prompt_text, intention, category, subcategory, severity)
            VALUES ($1, $2, $3, $4, $5)
        """, records)

        print(f"{len(all_attacks)}건의 공격 패턴 적재 성공!")
        await conn.close()

    except Exception as e:
        print(f"PostgreSQL 적재 실패: {e}")

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