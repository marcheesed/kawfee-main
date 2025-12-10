import sqlite3

conn = sqlite3.connect(r"dev_data5.db")
cursor = conn.cursor()

# Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    bio TEXT,
    pfp TEXT,
    custom_css TEXT,
    display_name TEXT,
    ip TEXT,
    privacy_policy_version INTEGER DEFAULT 0
)
""")

# Tags table
cursor.execute("""
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
)
""")

# Fanfiction table
cursor.execute("""
CREATE TABLE IF NOT EXISTS fanfics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    author TEXT,
    owner TEXT,
    fandom TEXT,
    age_rating TEXT,
    comments TEXT,
    kudos TEXT,
    content TEXT
)
""")

# Fanfic tags (many-to-many)
cursor.execute("""
CREATE TABLE IF NOT EXISTS fanfic_tags (
    fanfic_id INTEGER,
    tag_id INTEGER,
    PRIMARY KEY (fanfic_id, tag_id),
    FOREIGN KEY (fanfic_id) REFERENCES fanfics(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
)
""")

# Notes
cursor.execute("""
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,
    content TEXT
)
""")

# Site info
cursor.execute("""
CREATE TABLE IF NOT EXISTS site_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT
)
""")

# Blog posts
cursor.execute("""
CREATE TABLE IF NOT EXISTS blog_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,
    author TEXT,
    timestamp TEXT
)
""")

# Kudos (likes)
cursor.execute("""
CREATE TABLE IF NOT EXISTS kudos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    item_type TEXT, -- e.g., 'fanfic', 'blog', 'note'
    item_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# IP logs
cursor.execute("""
CREATE TABLE IF NOT EXISTS ip_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    timestamp TEXT,
    user_id INTEGER,
    username TEXT,
    page TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# User activity logs
cursor.execute("""
CREATE TABLE IF NOT EXISTS user_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT,
    timestamp TEXT,
    page TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# banned ips
cursor.execute("""
CREATE TABLE IF NOT EXISTS banned_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    username TEXT
)
""")

# invite codes
cursor.execute("""
CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT,
    created_at TIMESTAMP,
    used BOOLEAN DEFAULT 0,
    redeemed_by TEXT
)
""")


conn.commit()
conn.close()
print("All tables created.")
