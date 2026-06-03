import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def recreate_db():
    user = "postgres"
    password = "Shivraj@123456"
    host = "127.0.0.1"
    port = "5432"
    
    con = psycopg2.connect(dbname='postgres', user=user, host=host, password=password, port=port)
    con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = con.cursor()
    
    # Terminate other connections if any
    cur.execute("SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = 'Vulnerability_Scanner' AND pid <> pg_backend_pid();")
    
    cur.execute('DROP DATABASE IF EXISTS "Vulnerability_Scanner"')
    cur.execute('CREATE DATABASE vulnerability_scanner')
    print("Database recreated as 'vulnerability_scanner'")
    
    cur.close()
    con.close()

if __name__ == "__main__":
    recreate_db()
