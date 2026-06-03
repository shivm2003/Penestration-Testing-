import asyncio
from database import engine
from sqlalchemy import text

async def migrate():
    async with engine.begin() as conn:
        await conn.execute(text(
            "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_report_status VARCHAR DEFAULT 'none'"
        ))
        await conn.execute(text(
            "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS advanced_ai_report TEXT"
        ))
    print("Migration complete - both columns added to vulnerabilities table")

asyncio.run(migrate())
