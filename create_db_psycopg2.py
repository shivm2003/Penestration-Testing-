import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def create_db():
    # Password encoded in URL is usually for asyncpg/sqlalchemy, 
    # but here we use raw params.
    user = "postgres"
    password = "Shivraj@123456"
    host = "127.0.0.1"
    port = "5432"
    db_name = "Vulnerability_Scanner"

    try:
        # Connect to default postgres database
        con = psycopg2.connect(dbname='postgres', user=user, host=host, password=password, port=port)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        
        # Check if exists
        cur.execute(f"SELECT 1 FROM pg_database WHERE datname = '{db_name}'")
        exists = cur.fetchone()
        
        if not exists:
            cur.execute(f'CREATE DATABASE "{db_name}"')
            print(f"Database '{db_name}' created successfully via psycopg2!")
        else:
            print(f"Database '{db_name}' already exists.")
            
        cur.close()
        con.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_db()
