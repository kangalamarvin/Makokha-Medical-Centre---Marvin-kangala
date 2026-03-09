import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance', 'clinic.db')
DB_PATH = os.path.abspath(DB_PATH)

print('DB:', DB_PATH)
print('Exists:', os.path.exists(DB_PATH))

con = sqlite3.connect(DB_PATH)
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
print('Tables count:', len(tables))
print('Has alembic_version:', 'alembic_version' in tables)
print('First tables:', tables[:40])

if 'alembic_version' in tables:
    try:
        cur.execute('SELECT version_num FROM alembic_version')
        print('alembic_version rows:', cur.fetchall())
    except Exception as e:
        print('Failed to read alembic_version:', e)

con.close()
