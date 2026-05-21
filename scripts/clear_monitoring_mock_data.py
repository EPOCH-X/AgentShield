"""
이미 INSERT 된 dev_seed 모니터링 모의 데이터(employees / violations / usage_logs / 데모 스캔 세션)를 일괄 삭제.

dev_seed.py 가 더 이상 mock을 시드하지 않게 바뀌었지만, 과거 부팅에서 들어간 row 는 그대로 남아있다.
실제 운영/시연 흐름에서 챗봇 입력만 보이게 하려면 이 스크립트를 한 번 실행한다.

사용법:
    python -m scripts.clear_monitoring_mock_data           # 모의 직원/위반/사용로그 삭제 (데모 스캔은 유지)
    python -m scripts.clear_monitoring_mock_data --all     # 데모 스캔 세션까지 삭제
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import delete, select

from backend.database import async_session
from backend.models import Employee, TestResult, TestSession, UsageLog, Violation


MOCK_EMPLOYEE_IDS = ["E-1001", "E-1002", "E-1003", "E-1004", "E-1005"]
DEMO_SESSION_NAME = "데모 스캔 세션"


async def _delete_mock_monitoring(also_demo_scan: bool) -> None:
    async with async_session() as s:
        emp_ids = [
            row.id for row in (
                await s.scalars(
                    select(Employee).where(Employee.employee_id.in_(MOCK_EMPLOYEE_IDS))
                )
            ).all()
        ]

        if emp_ids:
            v_count = await s.scalar(
                select(Violation.id).where(Violation.employee_id.in_(emp_ids))
            )
            await s.execute(delete(Violation).where(Violation.employee_id.in_(emp_ids)))
            await s.execute(delete(UsageLog).where(UsageLog.employee_id.in_(emp_ids)))
            await s.execute(delete(Employee).where(Employee.id.in_(emp_ids)))
            print(f"[clear] mock 직원 {len(emp_ids)}명 + 연관 violations/usage_logs 삭제")
        else:
            print("[clear] mock 직원 row 없음 — 스킵")

        if also_demo_scan:
            sess = await s.scalar(
                select(TestSession).where(TestSession.project_name == DEMO_SESSION_NAME)
            )
            if sess:
                await s.execute(delete(TestResult).where(TestResult.session_id == sess.id))
                await s.execute(delete(TestSession).where(TestSession.id == sess.id))
                print("[clear] 데모 스캔 세션 + 결과 삭제")
            else:
                print("[clear] 데모 스캔 세션 row 없음 — 스킵")

        await s.commit()
    print("[clear] 완료")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="데모 스캔 세션까지 삭제")
    args = parser.parse_args()
    asyncio.run(_delete_mock_monitoring(also_demo_scan=args.all))
    return 0


if __name__ == "__main__":
    sys.exit(main())
