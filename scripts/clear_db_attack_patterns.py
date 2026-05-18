"""DB의 AttackPattern 테이블에서 빈/placeholder row를 정리한다.

`accepted.jsonl` 파일 기반 패턴(138개)을 사용할 것이므로 DB는 비워둔다.
백엔드와 동일한 async_session을 사용한다.
"""

import asyncio
from sqlalchemy import delete, select, func

from backend.database import async_session
from backend.models.attack_pattern import AttackPattern as AP


async def main() -> None:
    async with async_session() as db:
        before = await db.scalar(select(func.count()).select_from(AP)) or 0
        result = await db.execute(delete(AP))
        await db.commit()
        after = await db.scalar(select(func.count()).select_from(AP)) or 0
        print(f"deleted={result.rowcount} before={before} after={after}")


if __name__ == "__main__":
    asyncio.run(main())
