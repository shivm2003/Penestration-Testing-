from sqlalchemy.ext.asyncio import AsyncSession
from models import SystemLog

async def log_event(session: AsyncSession, target_id: int, agent_name: str, message: str, level: str = "INFO"):
    print(f"[{agent_name}] {message}")
    log = SystemLog(
        target_id=target_id,
        agent_name=agent_name,
        message=message,
        log_level=level
    )
    session.add(log)
    await session.commit()
