"""Initialize the audit database (SQLite by default).

Usage:
python scripts/init_db.py
"""
from persistence.db import init_db

if __name__ == '__main__':
    init_db()
    print('Database initialized.')
