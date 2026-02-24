import pickle
import sqlite3

API_KEY = "demo_hardcoded_key_123456789"

def unsafe_query(user_id: str):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect(":memory:")
    return conn.execute(query).fetchall()

def run_user_expression(user_expression: str):
    return eval(user_expression)

def load_untrusted_blob(raw_blob: bytes):
    return pickle.loads(raw_blob)