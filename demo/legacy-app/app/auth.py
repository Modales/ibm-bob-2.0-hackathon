"""Legacy authentication module — deliberately vulnerable, for demo purposes.

Contains seeded flaws for the Modernizer demo:
* md5 password hashing (weak crypto)
* SQL injection via f-string query built from request args (taint flow)
"""

import hashlib
import sqlite3

from flask import request


def verify_password(password: str, digest: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == digest


def get_user(conn: sqlite3.Connection):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn.cursor().execute(query)
