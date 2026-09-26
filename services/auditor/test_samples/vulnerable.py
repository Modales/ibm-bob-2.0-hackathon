from flask import request
import sqlite3

def get_user(conn):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn.cursor().execute(query)