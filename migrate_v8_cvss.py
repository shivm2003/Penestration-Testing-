import asyncio
from database import engine
from sqlalchemy import text

async def migrate():
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_score FLOAT"))
    print("Migration complete - cvss_score added to vulnerabilities.")

if __name__ == "__main__":
    asyncio.run(migrate())
