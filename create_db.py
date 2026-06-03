import asyncio
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

async def create_db():
    # Use the postgres default database to connect and create the new one
    conn_str = "postgresql://postgres:Shivraj%40123456@127.0.0.1:5432/postgres"
    db_name = "Vulnerability_Scanner"
    
    try:
        conn = await asyncpg.connect(conn_str)
        # Check if exists
        exists = await conn.fetchval(f"SELECT 1 FROM pg_database WHERE datname = '{db_name}'")
        if not exists:
            # asyncpg doesn't allow CREATE DATABASE inside a transaction
            # but we can close and reconnect or use a bypass if needed.
            # Actually, we can just run it.
            await conn.execute(f'CREATE DATABASE "{db_name}"')
            print(f"Database '{db_name}' created successfully!")
        else:
            print(f"Database '{db_name}' already exists.")
        await conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")

if __name__ == "__main__":
    asyncio.run(create_db())
