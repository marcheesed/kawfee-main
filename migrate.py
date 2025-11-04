import json
import sqlite3

# Load your old data JSON
with open("data.json", "r", encoding="utf-8") as f:
    old_data = json.load(f)

db_path = r"C:\kawfee\data.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# --- Migrate users ---
user_map = {}  # old username -> new user_id
for username, user in old_data["users"].items():
    cursor.execute(
        """
        INSERT INTO users (username, password, is_admin, bio, pfp, custom_css, display_name, ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            username,
            user["password"],
            int(user.get("is_admin", False)),
            user.get("bio", ""),
            user.get("pfp", ""),
            user.get("custom_css", ""),
            user.get("display_name", ""),
            user.get("ip", ""),
        ),
    )
    user_id = cursor.lastrowid
    user_map[username] = user_id

# --- Migrate tags ---
tag_map = {}  # tag name -> tag_id
for tag in old_data["tags"]:
    cursor.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
    cursor.execute("SELECT id FROM tags WHERE name = ?", (tag,))
    tag_id = cursor.fetchone()[0]
    tag_map[tag] = tag_id

# --- Migrate fanfics ---
fanfic_map = {}  # old fanfic id -> new fanfic_id
for f in old_data["fanfics"]:
    cursor.execute(
        """
        INSERT INTO fanfics (title, author, owner, fandom, age_rating, comments, kudos)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            f["title"],
            f["author"],
            f["owner"],
            f["fandom"],
            f.get("age_rating", ""),
            json.dumps(f.get("comments", [])),
            json.dumps(f.get("kudos", [])),
        ),
    )
    new_fanfic_id = cursor.lastrowid
    fanfic_map[f["id"]] = new_fanfic_id

    # Insert tags for fanfic
    for t in f.get("tags", []):
        if t in tag_map:
            cursor.execute(
                "INSERT INTO fanfic_tags (fanfic_id, tag_id) VALUES (?, ?)",
                (new_fanfic_id, tag_map[t]),
            )

    # Insert chapters
    for ch in f.get("chapters", []):
        cursor.execute(
            """
            INSERT INTO chapters (fanfic_id, title, content)
            VALUES (?, ?, ?)
        """,
            (new_fanfic_id, ch["title"], ch["content"]),
        )

# --- Migrate comments ---
# Comments are embedded within fanfics/comments, but if separate, handle accordingly

# --- Migrate notes ---
# Assuming old notes stored in old_data['notes'] as dict with keys like "1", "3", etc.
for note_id, note in old_data.get("notes", {}).items():
    cursor.execute(
        """
        INSERT INTO notes (owner, content) VALUES (?, ?)
    """,
        (note["owner"], note["content"]),
    )

# --- Migrate blog posts ---
for post_id, post in old_data.get("blog_posts", {}).items():
    cursor.execute(
        """
        INSERT INTO blog_posts (title, content, author, timestamp)
        VALUES (?, ?, ?, ?)
    """,
        (post["title"], post["content"], post["author"], post["timestamp"]),
    )

# --- Migrate IP logs ---
for log in old_data.get("ip_logs", []):
    cursor.execute(
        """
        INSERT INTO ip_logs (ip, timestamp, user_id, page)
        VALUES (?, ?, ?, ?)
    """,
        (
            log["ip"],
            log["timestamp"],
            user_map.get(log.get("user"), None),
            log.get("page", ""),
        ),
    )

# --- Migrate user logs ---
for username, logs in old_data.get("user_logs", {}).items():
    user_id = user_map.get(username)
    for log in logs:
        cursor.execute(
            """
            INSERT INTO user_logs (user_id, ip, timestamp, page)
            VALUES (?, ?, ?, ?)
        """,
            (user_id, log["ip"], log["timestamp"], log["page"]),
        )

conn.commit()
conn.close()
print("Migration complete!")
