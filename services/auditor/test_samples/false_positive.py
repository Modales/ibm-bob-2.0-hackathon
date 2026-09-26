from flask import request

def unsafe_lookup(conn):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn.cursor().execute(query)

def totally_safe_function(conn, user_id):
    conn.cursor().execute(user_id)
