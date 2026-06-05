from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.engine.url import make_url
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

# Default local DB URL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:Shivraj%40123456@127.0.0.1:5432/vulnerability_scanner")

engine = create_async_engine(DATABASE_URL, echo=False)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def ensure_database_exists():
    url = make_url(DATABASE_URL)
    if not url.drivername.startswith("postgresql"):
        return

    target_db = url.database
    if not target_db or target_db == "postgres":
        return

    admin_args = {
        "user": url.username,
        "password": url.password,
        "host": url.host or "127.0.0.1",
        "port": url.port or 5432,
        "database": "postgres",
    }

    conn = await asyncpg.connect(**admin_args)
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", target_db)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{target_db}"')
    finally:
        await conn.close()
