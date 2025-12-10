import sqlite3

import bcrypt

# Hash the password
plain_password = "password"
hashed_password = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())

# Convert hashed password to string for storage
hashed_password_str = hashed_password.decode("utf-8")

# Connect to the database
conn = sqlite3.connect(r"dev_data5.db")
cursor = conn.cursor()

# Insert the test user with hashed password
cursor.execute(
    """
INSERT INTO users (username, password, is_admin, bio, pfp, custom_css, display_name, ip, privacy_policy_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
    (
        "admin",  # username
        hashed_password_str,  # password (hashed)
        1,  # is_admin (True)
        "This is a bio",  # bio
        "",  # pfp
        "",  # custom_css
        "",  # display_name
        "127.0.0.1",  # ip
        "0",  # pp ver
    ),
)

# Commit the changes and close connection
conn.commit()
conn.close()

print("Test user inserted with hashed password.")
