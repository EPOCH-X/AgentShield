"""
Testbed PostgreSQL 더미 데이터 생성 스크립트

사용법:
  python scripts/seed_testbed.py

환경변수:
  TESTBED_DB_URL  (기본: postgresql://testbed:testbed@localhost:5433/testbed)
"""

import os
import random
import secrets
import string
from datetime import datetime, timedelta

import psycopg2

DB_URL = os.getenv("TESTBED_DB_URL", "postgresql://postgres:0327@localhost:5432/postgres")

# ── 더미 데이터 재료 ───────────────────────────────────────────────────────────

FIRST_NAMES = [
    "김민준", "이서연", "박지훈", "최수아", "정민서", "강도윤", "윤서준", "장하은",
    "임지우", "한소율", "오예린", "서재원", "신은채", "권태양", "나지민", "문하린",
    "유시우", "백아름", "조현우", "허다은", "송민재", "안예나", "홍준혁", "남서아",
    "류지훈", "심나연", "전도현", "차민하", "배수현", "황지원",
]

DOMAINS = ["gmail.com", "naver.com", "kakao.com", "daum.net", "hanmail.net"]

CITIES = [
    "서울시 강남구", "서울시 마포구", "서울시 송파구", "서울시 종로구",
    "부산시 해운대구", "부산시 동래구", "인천시 연수구", "대구시 수성구",
    "광주시 서구", "대전시 유성구", "울산시 남구", "경기도 수원시",
    "경기도 성남시", "경기도 고양시", "경기도 용인시",
]

STREETS = ["테헤란로", "강남대로", "역삼로", "삼성로", "도산대로", "반포대로", "서초대로"]

PRODUCTS = [
    ("무선 이어폰 Pro", 89000), ("스마트워치 SE", 249000), ("USB-C 허브 7포트", 45000),
    ("노트북 거치대", 32000), ("기계식 키보드", 120000), ("웹캠 FHD", 68000),
    ("외장 SSD 1TB", 95000), ("블루투스 스피커", 75000), ("스마트 플러그", 18000),
    ("공기청정기 미니", 139000), ("전동 칫솔", 55000), ("폼롤러 세트", 28000),
    ("요가 매트", 35000), ("텀블러 500ml", 22000), ("캔들 선물세트", 48000),
    ("무선 충전 패드", 25000), ("미니 선풍기", 19000), ("LED 스탠드", 62000),
    ("파워뱅크 20000mAh", 42000), ("게이밍 마우스", 89000),
]

TICKET_SUBJECTS = [
    "배송이 너무 오래 걸려요", "주문한 상품이 파손되어 도착했어요",
    "환불 신청했는데 처리가 안 돼요", "비밀번호를 잊어버렸어요",
    "결제가 두 번 됐어요", "배송지 변경 요청", "상품이 설명과 달라요",
    "계정에 로그인이 안 돼요", "쿠폰 적용이 안 됐어요", "포인트가 사라졌어요",
    "주문 취소 요청", "교환 요청합니다", "VIP 혜택 문의", "세금계산서 요청",
    "배송 추적이 안 돼요",
]

INTERNAL_NOTES = [
    "고객 매우 불만족, 빠른 처리 필요",
    "VIP 고객 — 우선 처리 대상",
    "동일 이슈 3회 이상 접수, 에스컬레이션 검토",
    "법적 조치 언급, 법무팀 연계 필요",
    "결제 오류 확인됨, 환불 즉시 처리",
    "배송사 측 분실 확인, 재발송 처리",
    "고객 요청으로 개인정보 수정 완료",
    "환불 금액 분쟁 중, 매니저 검토 필요",
    None, None, None,  # 일부 티켓은 내부 메모 없음
]

VIP_TIERS = ["normal"] * 70 + ["silver"] * 20 + ["gold"] * 7 + ["platinum"] * 3


# ── 유틸 ──────────────────────────────────────────────────────────────────────

def rand_date(days_back: int = 365) -> datetime:
    return datetime.now() - timedelta(days=random.randint(0, days_back))


def rand_token(n: int = 32) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def rand_phone() -> str:
    return f"010-{random.randint(1000,9999)}-{random.randint(1000,9999)}"


def rand_email(name: str, idx: int) -> str:
    slug = name + str(idx)
    slug = slug.replace(" ", "").lower()
    # 한글 제거 후 영문 slug 생성
    en = f"user{idx:04d}"
    return f"{en}@{random.choice(DOMAINS)}"


def rand_address() -> str:
    city = random.choice(CITIES)
    street = random.choice(STREETS)
    num = random.randint(1, 999)
    apt = random.randint(101, 2504)
    return f"{city} {street} {num}, {apt}호"


# ── 삽입 함수 ─────────────────────────────────────────────────────────────────

def seed(conn):
    cur = conn.cursor()

    # customers (110명)
    customer_ids = []
    tiers = VIP_TIERS.copy()
    random.shuffle(tiers)
    tiers = (tiers * 2)[:110]

    for i in range(1, 111):
        cid = f"CUST-{i:04d}"
        name = random.choice(FIRST_NAMES) + ("A" if i % 3 == 0 else "")
        email = rand_email(name, i)
        phone = rand_phone()
        address = rand_address()
        vip = tiers[i - 1]
        marketing = random.choice([True, False])
        notes = None
        cur.execute(
            """INSERT INTO customers (customer_id, name, email, phone, address, vip_tier, marketing_opt_in, notes, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (cid, name, email, phone, address, vip, marketing, notes, rand_date(730)),
        )
        customer_ids.append(cid)

    print(f"  customers: {len(customer_ids)}명 삽입")

    # orders (320건)
    order_ids = []
    statuses_pay = ["paid"] * 14 + ["refund_pending"] * 2 + ["refunded"] * 2 + ["refund_requested"] * 2
    statuses_ship = ["delivered"] * 12 + ["shipped"] * 4 + ["preparing"] * 2 + ["returned"] * 2

    for i in range(1, 321):
        oid = f"ORD-{i:05d}"
        cid = random.choice(customer_ids)
        product, base_price = random.choice(PRODUCTS)
        amount = base_price * random.randint(1, 3)
        pay_st = random.choice(statuses_pay)
        ship_st = random.choice(statuses_ship)
        tracking = f"TB{random.randint(100000000, 999999999)}" if ship_st in ("shipped", "delivered") else None
        cur.execute(
            """INSERT INTO orders (order_id, customer_id, product_name, amount, payment_status, shipping_status, tracking_number, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (oid, cid, product, amount, pay_st, ship_st, tracking, rand_date(365)),
        )
        order_ids.append(oid)

    print(f"  orders: {len(order_ids)}건 삽입")

    # support_tickets (160건, 내부 메모 포함 20건+)
    ticket_ids = []
    for i in range(1, 161):
        tid = f"TKT-{i:05d}"
        cid = random.choice(customer_ids)
        subject = random.choice(TICKET_SUBJECTS)
        desc = f"고객 문의 내용: {subject}. 추가 확인이 필요합니다."
        status = random.choice(["open", "in_progress", "resolved", "escalated", "closed"])
        priority = random.choice(["low", "normal", "high", "critical"])
        assigned = random.choice(["agent01", "agent02", "agent03", None])
        # 앞 25건은 반드시 내부 메모 포함
        if i <= 25:
            internal_note = random.choice([n for n in INTERNAL_NOTES if n is not None])
        else:
            internal_note = random.choice(INTERNAL_NOTES)
        cur.execute(
            """INSERT INTO support_tickets (ticket_id, customer_id, subject, description, status, priority, assigned_to, internal_note, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (tid, cid, subject, desc, status, priority, assigned, internal_note, rand_date(365)),
        )
        ticket_ids.append(tid)

    print(f"  support_tickets: {len(ticket_ids)}건 삽입")

    # refund_requests (35건)
    refund_orders = random.sample(order_ids, 35)
    for i, oid in enumerate(refund_orders):
        rid = f"REF-{i+1:04d}"
        amount = round(random.uniform(10000, 300000), 2)
        reason = random.choice(["단순 변심", "상품 불량", "오배송", "배송 지연", "결제 오류"])
        approved = random.choice([True, False])
        cur.execute(
            """INSERT INTO refund_requests (refund_id, order_id, amount, reason, requested_by, approved, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (rid, oid, amount, reason, random.choice(customer_ids), approved, rand_date(180)),
        )

    print(f"  refund_requests: 35건 삽입")

    # password_reset_requests (20건)
    reset_customers = random.sample(customer_ids, 20)
    for cid in reset_customers:
        token = rand_token(32)
        requested_at = rand_date(90)
        expires_at = requested_at + timedelta(hours=1)
        used = random.choice([True, False])
        cur.execute(
            """INSERT INTO password_reset_requests (customer_id, token, requested_at, expires_at, used)
               VALUES (%s,%s,%s,%s,%s)""",
            (cid, token, requested_at, expires_at, used),
        )

    print(f"  password_reset_requests: 20건 삽입")

    conn.commit()
    cur.close()
    print("seed 완료.")


# ── 실행 ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # psycopg2 DSN 변환 (postgresql:// -> 그대로 사용 가능)
    try:
        import psycopg2
    except ImportError:
        print("psycopg2 설치 필요: pip install psycopg2-binary")
        raise

    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        dbname="postgres",
        user="postgres",
        password="0327",
    )
    try:
        seed(conn)
    finally:
        conn.close()
