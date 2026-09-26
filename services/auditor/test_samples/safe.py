from flask import request
import sqlite3

def get_user(conn):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = ?"
    conn.cursor().execute(query, (user_id,))