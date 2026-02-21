import sqlite3

def get_user(conn: sqlite3.Connection, user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return conn.execute(query).fetchall()

API_KEY = "hardcoded-demo-api-key-123456"
