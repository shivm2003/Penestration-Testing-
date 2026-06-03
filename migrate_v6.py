import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:Shivraj%40123456@127.0.0.1:5432/vulnerability_scanner")

async def migrate():
    engine = create_async_engine(DATABASE_URL)
    async with engine.begin() as conn:
        print("[MIGRATION] Adding 'path' and 'method' columns to 'vulnerabilities' table...")
        try:
            await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS path VARCHAR;"))
            await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS method VARCHAR;"))
            print("[SUCCESS] Database schema updated to Phase 6 standards.")
        except Exception as e:
            print(f"[ERROR] Migration failed: {e}")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(migrate())
