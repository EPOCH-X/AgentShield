import asyncio
from backend.database import async_session
from backend.models.user import User
from sqlalchemy import select

async def check():
    async with async_session() as db:
        result = await db.execute(select(User))
        users = result.scalars().all()
        for u in users:
            print(f"Name: {u.name}, Email: {u.email}, Status: {u.status}")

asyncio.run(check())