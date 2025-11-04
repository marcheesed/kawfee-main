import sqlite3
from werkzeug.security import generate_password_hash


def get_db_connection():
    conn = sqlite3.connect("data.db", check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 30000")  # 30 seconds
    conn.row_factory = sqlite3.Row
    return conn


def fix_invalid_password_hashes():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Replace 'users' with your actual users table name
    cursor.execute("SELECT username, password FROM users")
    users = cursor.fetchall()

    for user in users:
        username = user["username"]
        password_hash = user["password"]
        # Check if hash looks valid (starts with known prefix)
        if not password_hash or not (
            password_hash.startswith("$2b$")
            or password_hash.startswith("$pbkdf2_sha256$")
        ):
            print(f"Resetting password for user: {username}")
            # Generate a new password hash (you might want to generate a random password here)
            new_hash = generate_password_hash("temporarypassword")  # Or generate random
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?", (new_hash, username)
            )
            print(f"Password for {username} reset to default password.")
    conn.commit()
    conn.close()


# Run this script once to fix all invalid hashes
fix_invalid_password_hashes()
