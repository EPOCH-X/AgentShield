"""Database URL helpers shared by async and sync SQLAlchemy engines."""

from __future__ import annotations

from sqlalchemy.engine import make_url


def make_sync_database_url(database_url: str) -> str:
    """Convert the app async URL into a psycopg2-compatible sync URL.

    asyncpg accepts ``?ssl=require`` while psycopg2 expects
    ``?sslmode=require``. Keeping this conversion in one place prevents the
    monitoring audit path from silently using a different database driver
    contract than the rest of the backend.
    """
    url = make_url(database_url)

    if url.drivername == "postgresql+asyncpg":
        url = url.set(drivername="postgresql+psycopg2")

    query = dict(url.query)
    ssl_value = query.pop("ssl", None)
    if ssl_value and "sslmode" not in query:
        query["sslmode"] = ssl_value

    return url.set(query=query).render_as_string(hide_password=False)
