"""
[R4] 데이터 적재 — ChromaDB에 방어 패턴/공격 데이터 적재

세부기획서 섹션 2-2 참조.
defense_patterns: ~100건 수동 수집
attack_results: Phase 2에서 자동 축적
"""

# TODO: [R4] 방어 패턴 적재 (R2: 공격 데이터 적재 부분도 이 파일 사용)

import hashlib
import os
import sys
from datetime import datetime, timezone
from typing import Any

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


def _normalize_defense_text(s: str) -> str:
    return " ".join(str(s or "").strip().split())


def _enrich_defense_fields(item: dict[str, Any]) -> dict[str, Any]:
    """defense_code JSON에서 defended_response / defense_rationale 보강."""
    out = dict(item)
    defended_response = str(out.get("defended_response") or "")
    defense_rationale = str(out.get("defense_rationale") or "")
    defense_code = out.get("defense_code", "")
    if isinstance(defense_code, str) and defense_code.strip().startswith("{"):
        try:
            parsed_code = json.loads(defense_code)
            if not defended_response:
                defended_response = str(parsed_code.get("defended_response") or "")
            if not defense_rationale:
                defense_rationale = str(parsed_code.get("defense_rationale") or "")
        except Exception:
            pass
    out["defended_response"] = defended_response
    out["defense_rationale"] = defense_rationale
    return out


def compute_defense_pattern_id(item: dict[str, Any]) -> str:
    """
    전역 패턴 식별자: category + failure_mode + 정규화된 방어 본문 기반 SHA256(hex).
    Chroma 문서 id로 사용 (세션/ test_result_id 와 분리).
    """
    it = _enrich_defense_fields(item)
    category = str(it.get("category", "Unknown")).strip()
    failure_mode = str(it.get("failure_mode", "")).strip()
    defended = _normalize_defense_text(str(it.get("defended_response") or ""))
    rationale = _normalize_defense_text(str(it.get("defense_rationale") or ""))
    canonical = json.dumps(
        {
            "category": category,
            "failure_mode": failure_mode,
            "defended_response": defended,
            "defense_rationale": rationale,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_defense_document_and_base_metadata(
    item: dict[str, Any],
    *,
    pattern_id: str,
    legacy_row_id: str,
) -> tuple[str, dict[str, Any]]:
    it = _enrich_defense_fields(item)
    category = str(it.get("category", "Unknown"))
    title = str(it.get("title", "No Title"))
    source = str(it.get("source", "custom"))
    attack_prompt = str(it.get("attack_prompt") or "")
    target_response = str(it.get("target_response") or "")
    defended_response = str(it.get("defended_response") or "")
    defense_rationale = str(it.get("defense_rationale") or "")
    judge_reason = str(it.get("judge_reason") or "")
    failure_mode = str(it.get("failure_mode") or "")
    verify_result = str(it.get("verify_result") or "")
    defense_code = it.get("defense_code", "")

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
    meta: dict[str, Any] = {
        "pattern_id": pattern_id,
        "source_id": legacy_row_id,
        "legacy_source_id": legacy_row_id,
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
        "defense_code": defense_code if isinstance(defense_code, str) else json.dumps(defense_code, ensure_ascii=False),
    }
    return document, meta


def _parse_int_meta(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _merge_sessions_json(existing_json: str, session_id: str) -> str:
    try:
        cur = json.loads(existing_json) if existing_json else []
    except json.JSONDecodeError:
        cur = []
    if not isinstance(cur, list):
        cur = []
    if session_id and session_id not in cur:
        cur.append(session_id)
    return json.dumps(cur, ensure_ascii=False)


def _merge_defense_ids_json(existing_json: str, defense_id: str) -> str:
    try:
        cur = json.loads(existing_json) if existing_json else []
    except json.JSONDecodeError:
        cur = []
    if not isinstance(cur, list):
        cur = []
    if defense_id and defense_id not in cur:
        cur.append(defense_id)
    return json.dumps(cur, ensure_ascii=False)


def upsert_defense_pattern_items(
    items: list[dict[str, Any]],
    *,
    session_id: str,
    full_replace: bool = False,
) -> int:
    """
    Phase4 등 런타임: 이번 배치만 Chroma defense_patterns에 반영 (디렉터리 전체 스캔 없음).
    pattern_id(해시) 기준 upsert; 동일 패턴 재적재 시 seen_count / source_sessions 갱신.

    full_replace=True: 배치 적재(풀 리빌드) 시 기존 Chroma 메타와 합치지 않고 이 행 기준으로 덮어씀.
    """
    if not items:
        return 0

    print("\n방어 패턴 ChromaDB 증분 적재 시작\n", flush=True)

    # 동일 pattern_id가 배치 내 중복이면 마지막 행이 문서/본문을 대표
    by_pid: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        it = _enrich_defense_fields(item)
        pid = compute_defense_pattern_id(it)
        by_pid[pid] = it

    unique_ids = list(by_pid.keys())
    existing_metas: dict[str, dict[str, Any]] = {}
    if not full_replace and unique_ids:
        try:
            got = rag_client.defense_col.get(ids=unique_ids, include=["metadatas"])
            for i, rid in enumerate(got.get("ids") or []):
                mlist = got.get("metadatas") or []
                if i < len(mlist) and isinstance(mlist[i], dict):
                    existing_metas[str(rid)] = mlist[i]
        except Exception:
            existing_metas = {}

    ids: list[str] = []
    docs: list[str] = []
    metas: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for pid, it in by_pid.items():
        legacy_id = str(it.get("id", "")).strip() or str(uuid.uuid4())
        document, base_meta = _build_defense_document_and_base_metadata(
            it, pattern_id=pid, legacy_row_id=legacy_id
        )
        defense_id = legacy_id

        if full_replace:
            meta = dict(base_meta)
            meta["defense_id"] = defense_id
            meta["session_id"] = session_id
            meta["seen_count"] = 1
            meta["source_sessions"] = json.dumps([session_id] if session_id else [], ensure_ascii=False)
            meta["defense_ids_seen"] = json.dumps([defense_id], ensure_ascii=False)
            meta["last_seen_at"] = now
        else:
            old = existing_metas.get(pid)
            seen = 1
            src_sessions = json.dumps([session_id] if session_id else [], ensure_ascii=False)
            def_ids_json = json.dumps([defense_id], ensure_ascii=False)
            if old:
                seen = _parse_int_meta(old.get("seen_count"), 0) + 1
                src_sessions = _merge_sessions_json(str(old.get("source_sessions") or ""), session_id)
                def_ids_json = _merge_defense_ids_json(str(old.get("defense_ids_seen") or ""), defense_id)
            meta = dict(base_meta)
            meta["defense_id"] = defense_id
            meta["session_id"] = session_id
            meta["seen_count"] = seen
            meta["source_sessions"] = src_sessions
            meta["defense_ids_seen"] = def_ids_json
            meta["last_seen_at"] = now

        # Chroma 메타데이터는 문자열/숫자 등 단순 타입 권장
        meta_flat: dict[str, Any] = {}
        for k, v in meta.items():
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                meta_flat[k] = v
            else:
                meta_flat[k] = str(v)

        ids.append(pid)
        docs.append(document)
        metas.append(meta_flat)

    try:
        rag_client.defense_col.upsert(ids=ids, documents=docs, metadatas=metas)
        print(f"{len(ids)}건의 방어 패턴 증분 적재 완료 (배치 입력 {len(items)}건, 고유 pattern {len(ids)})\n", flush=True)
        return len(ids)
    except Exception as e:
        print(f"ChromaDB 증분 적재 실패: {e}", flush=True)
        return 0


def ingest_defense_patterns() -> None:
    """
    data/defense_patterns 디렉터리 전체를 읽어 Chroma와 동기화 (배치/리빌드 전용).
    런타임 Phase4 경로에서는 호출하지 말고 upsert_defense_pattern_items를 사용한다.
    """
    print("\n방어 패턴 ChromaDB 전체 디렉터리 적재 시작\n", flush=True)
    if not os.path.exists(DEFENSE_DATA_DIR):
        print(f"방어 패턴 데이터 디렉토리 '{DEFENSE_DATA_DIR}'가 존재하지 않습니다.")
        return

    all_patterns: list[dict[str, Any]] = []
    for filename in os.listdir(DEFENSE_DATA_DIR):
        if filename.endswith((".json", ".jsonl")):
            filepath = os.path.join(DEFENSE_DATA_DIR, filename)
            all_patterns.extend(smart_json_loader(filepath))

    if not all_patterns:
        print("적재할 방어 패턴 데이터가 없습니다.")
        return

    n = upsert_defense_pattern_items(
        all_patterns,
        session_id="ingest:defense_patterns_full_dir",
        full_replace=True,
    )
    print(f"전체 적재 처리 완료: 입력 {len(all_patterns)}건 -> 고유 pattern upsert {n}건\n", flush=True)

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