import json
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    abort,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from jinja2 import pass_environment
import bleach
from datetime import datetime, timedelta
import bcrypt
from typing import Any
import ast
import sqlite3
import time


def get_db_connection():
    conn = sqlite3.connect("new.db", check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 30000")  # 30 seconds
    conn.row_factory = sqlite3.Row
    return conn


def execute_with_retry(cursor, query, params=(), retries=5, delay=0.1):
    for attempt in range(retries):
        try:
            cursor.execute(query, params)
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                time.sleep(delay)
            else:
                raise
    raise sqlite3.OperationalError("Database is locked, retries exhausted")


def get_all_users():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return [dict(row) for row in users]


def get_user(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def save_users(user):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password=?, is_admin=?, bio=?, pfp=?, custom_css=?, display_name=?, ip=? WHERE username=?",
        (
            user["password"],
            user["is_admin"],
            user["bio"],
            user["pfp"],
            user["custom_css"],
            user["display_name"],
            user["ip"],
            user["username"],
        ),
    )
    conn.commit()
    conn.close()


def create_user(user_data):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO users (username, password, is_admin, bio, pfp, custom_css, display_name, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_data["username"],
            user_data["password"],
            user_data["is_admin"],
            user_data["bio"],
            user_data["pfp"],
            user_data["custom_css"],
            user_data["display_name"],
            user_data["ip"],
        ),
    )
    conn.commit()
    conn.close()


def update_user(user_data):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password=?, is_admin=?, bio=?, pfp=?, custom_css=?, display_name=?, ip=? WHERE username=?",
        (
            user_data["password"],
            user_data["is_admin"],
            user_data["bio"],
            user_data["pfp"],
            user_data["custom_css"],
            user_data["display_name"],
            user_data["ip"],
            user_data["username"],
        ),
    )
    conn.commit()
    conn.close()


note: Any = None

app = Flask(__name__)
app.secret_key = "your_secret_key"

os.makedirs(os.path.join(app.static_folder, "pfps"), exist_ok=True)

ALLOWED_TAGS = [
    "b",
    "i",
    "u",
    "em",
    "strong",
    "a",
    "p",
    "br",
    "div",
    "span",
    "img",
    "style",
    "center",
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "div": ["style"],
    "span": ["style"],
    "img": ["src", "alt", "title", "width", "height"],
    "*": ["style"],
}

ALLOWED_STYLES = [
    "color",
    "background-color",
    "border-radius",
    "font-weight",
    "text-align",
    "font-style",
    "text-decoration",
    "background-image",
    "background-position",
    "background-size",
    "background-repeat",
]


def sanitize_bio(html_content):
    return bleach.clean(
        html_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True
    )


NOTE_ALLOWED_TAGS = [
    "b",
    "i",
    "u",
    "a",
    "p",
    "br",
    "img",
    "em",
    "strong",
    "code",
    "pre",
    "bold",
    "italic",
    "span",
]
NOTE_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "img": ["src", "alt", "title", "width", "height"],
}


def sanitize_note_content(content):
    return bleach.clean(
        content, tags=NOTE_ALLOWED_TAGS, attributes=NOTE_ALLOWED_ATTRIBUTES, strip=True
    )


def log_ip(username=None, page=None):
    ip = request.remote_addr
    now = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if username:
            # Check existing log
            cursor.execute(
                """
                SELECT * FROM ip_logs
                WHERE ip = ? AND username = ? AND timestamp > ?
                """,
                (ip, username, (datetime.now() - timedelta(minutes=10)).isoformat()),
            )
            existing_log = cursor.fetchone()

            if existing_log:
                # Update timestamp
                execute_with_retry(
                    cursor,
                    """
                    UPDATE ip_logs SET timestamp = ?, page = ? WHERE id = ?
                """,
                    (now, page, existing_log["id"]),
                )
            else:
                # Insert new log
                execute_with_retry(
                    cursor,
                    """
                    INSERT INTO ip_logs (ip, timestamp, username, page)
                    VALUES (?, ?, ?, ?)
                """,
                    (ip, now, username, page),
                )
        else:
            # Log anonymous user
            execute_with_retry(
                cursor,
                """
                INSERT INTO ip_logs (ip, timestamp, username, page)
                VALUES (?, ?, ?, ?)
            """,
                (ip, now, None, page),
            )
        conn.commit()
    finally:
        conn.close()


# helper to check login status :)
def logged_in():
    return "username" in session


def is_admin():
    if not is_logged_in():
        return False
    username = session["username"]
    user = get_user(username)
    if user:
        return user.get("is_admin", False)
    return False


## above is refactored


def get_banned_ips():
    conn = get_db_connection()
    ips = conn.execute("SELECT ip FROM banned_ips").fetchall()
    conn.close()
    return {row["ip"] for row in ips}


def is_ip_banned(ip):
    conn = get_db_connection()
    result = conn.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return result is not None


def save_banned_ip(ip):
    conn = get_db_connection()
    # Check if IP already exists to prevent duplicates
    existing = conn.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip,)).fetchone()
    if not existing:
        conn.execute("INSERT INTO banned_ips (ip) VALUES (?)", (ip,))
        conn.commit()
    conn.close()


def unban_ip(ip):
    conn = get_db_connection()
    conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(400)
def handle_400(error):
    return render_template("errors/400.html"), 400


@app.before_request
def check_ban():
    print("Session data:", session)
    ip = request.remote_addr
    if is_ip_banned(ip):
        abort(403)


def get_site_info():
    conn = get_db_connection()
    site_info = conn.execute("SELECT * FROM site_info LIMIT 1").fetchone()
    conn.close()
    print("Fetched site_info:", site_info)
    if site_info:
        site_info_dict = dict(site_info)
        # Ensure 'content' key exists
        if "content" not in site_info_dict:
            site_info_dict["content"] = ""
        return site_info_dict
    else:
        print("No site info found in database.")
        return {"content": ""}


def get_blog_posts():
    conn = get_db_connection()
    posts = conn.execute("SELECT * FROM blog_posts").fetchall()
    conn.close()
    return [dict(post) for post in posts]


def get_fanfics():
    conn = get_db_connection()
    fanfics = conn.execute("SELECT * FROM fanfics").fetchall()

    fanfics_with_tags = []

    for f in fanfics:
        fanfic_id = f["id"]
        # Fetch tags for this fanfic
        cursor = conn.execute(
            """
            SELECT t.name FROM tags t
            JOIN fanfic_tags ft ON t.id = ft.tag_id
            WHERE ft.fanfic_id = ?
        """,
            (fanfic_id,),
        )
        tags = [row["name"] for row in cursor.fetchall()]

        # Convert fanfic row to dict and add tags
        fanfic_dict = dict(f)
        fanfic_dict["tags"] = tags

        fanfics_with_tags.append(fanfic_dict)

    conn.close()
    return fanfics_with_tags


def update_user_password(username, hashed_password):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password = ? WHERE username = ?", (hashed_password, username)
    )
    conn.commit()
    conn.close()


def is_logged_in():
    return "username" in session


@app.route("/")
def index():
    # Fetch blog posts and fanfics from DB
    blog_posts = get_blog_posts()
    fanfics_list = get_fanfics()

    # Generate posts list
    posts = [
        {
            "id": post["id"],
            "title": post["title"],
            "content": post["content"],
            "author": post["author"],
            "timestamp": post["timestamp"],
        }
        for post in blog_posts
    ]
    posts.sort(key=lambda x: x["timestamp"], reverse=True)
    latest_post = posts[0] if posts else None

    # Logging IP
    log_ip(username=session.get("username"), page=request.path)

    # Format latest post timestamp
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # Get filter queries
    search_query = request.args.get("search", "").lower()
    author_query = request.args.get("author", "").lower()
    filter_tag = request.args.get("tag", "").lower()
    fandom_search = request.args.get("fandom", "").lower()

    # Load fanfics from DB and parse JSON fields safely
    fanfics = []
    for f in fanfics_list:
        # handle tags
        tags_data = f.get("tags", [])
        if isinstance(tags_data, str):
            if tags_data.strip():
                try:
                    f["tags"] = json.loads(tags_data)
                except:
                    f["tags"] = []
            else:
                f["tags"] = []
        else:
            f["tags"] = tags_data

        # handle fandoms
        fandoms_data = f.get("fandoms", [])
        if isinstance(fandoms_data, str):
            if fandoms_data.strip():
                try:
                    f["fandoms"] = json.loads(fandoms_data)
                except:
                    f["fandoms"] = []
            else:
                f["fandoms"] = []
        else:
            f["fandoms"] = fandoms_data

        fanfics.append(f)

    # ---- Filtering logic ----
    filtered_fanfics = []

    for f in fanfics:
        tags = f.get("tags", [])
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except:
                tags = []

        fandoms = f.get("fandoms", [])
        if isinstance(fandoms, str):
            try:
                fandoms = json.loads(fandoms)
            except:
                fandoms = []

        combined_fields = (
            f.get("title", "").lower()
            + f.get("author", "").lower()
            + " ".join(tag.lower() for tag in tags)
        )

        match_search = True
        if search_query:
            match_search = search_query in combined_fields

        match_author = True
        if author_query:
            match_author = author_query in f.get("author", "").lower()

        match_tag = True
        if filter_tag:
            match_tag = filter_tag in (tag.lower() for tag in tags)

        match_fandom = True
        if fandom_search:
            match_fandom = any(fandom_search in fandom.lower() for fandom in fandoms)

        if match_search and match_author and match_tag and match_fandom:
            filtered_fanfics.append(f)

    # Calculate top tags
    tag_counts = {}
    for f in fanfics:
        tags = f.get("tags", [])
        # Ensure tags is a list
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except:
                tags = [tags]
        elif not isinstance(tags, list):
            tags = [tags]

        # Count each tag (must be string)
        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    top_tags = [
        tag
        for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[
            :5
        ]
    ]

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 6
    total_fanfics = len(filtered_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = filtered_fanfics[start:end]

    return render_template(
        "index.html",
        fanfics=display_fanfics,
        site_info=get_site_info(),
        top_tags=top_tags,
        latest_post=latest_post,
        current_page=page,
        total_pages=total_pages,
        search=request.args.get("search", ""),
        author=request.args.get("author", ""),
        tag=request.args.get("tag", ""),
        fandom=request.args.get("fandom", ""),
        is_logged_in=is_logged_in(),
        is_admin=is_admin(),
        # other variables if needed...
    )


@app.route("/filter/tag/<path:tag>")
def filter_by_single_tag(tag):
    # Fetch data directly from the database
    fanfics_list = get_fanfics()
    blog_posts = get_blog_posts()

    # Fetch site info and convert to dict if needed
    site_info_row = get_site_info()
    if isinstance(site_info_row, dict):
        site_info = site_info_row
    elif hasattr(site_info_row, "_asdict"):  # for sqlite3.Row
        site_info = dict(site_info_row)
    else:
        site_info = dict(site_info_row)  # fallback

    print("Fetched site_info:", site_info)

    # Convert blog posts to desired format
    posts = [
        {
            "id": post["id"],
            "title": post["title"],
            "content": post["content"],
            "author": post["author"],
            "timestamp": post["timestamp"],
        }
        for post in blog_posts
    ]

    # Sort posts by timestamp descending
    posts.sort(key=lambda x: x["timestamp"], reverse=True)

    # Latest post
    latest_post = posts[0] if posts else None

    # Log IP
    log_ip(username=session.get("username"), page=request.path)
    print(
        f"Logging IP: {request.remote_addr}, User: {session.get('username')}, Page: {request.path}"
    )

    # Format latest post timestamp
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # Collect all tags for display
    all_tags = set()
    for f in fanfics_list:
        tags_data = f.get("tags", [])
        if isinstance(tags_data, str):
            if tags_data.strip():
                try:
                    tags_data = json.loads(tags_data)
                except:
                    tags_data = []
        for t in tags_data:
            # Convert list to string to avoid unhashable errors
            if isinstance(t, list):
                t_str = json.dumps(t, sort_keys=True)
            elif isinstance(t, str):
                try:
                    t_parsed = json.loads(t)
                    if isinstance(t_parsed, list):
                        t_str = json.dumps(t_parsed, sort_keys=True)
                    else:
                        t_str = t
                except:
                    t_str = t
            else:
                t_str = str(t)
            all_tags.add(t_str)

    # Initialize data dictionary
    data = {}
    data["tags"] = list(all_tags)

    # Filter fanfics by the specified tag
    filtered_fanfics = [f for f in fanfics_list if tag in f.get("tags", [])]

    # Get current search filters
    search_query = request.args.get("search", "")
    author_query = request.args.get("author", "")

    # Count tags for top tags
    tag_counts = {}
    for f in fanfics_list:
        for t in f.get("tags", []):
            # Handle t being list or string
            if isinstance(t, list):
                t_parsed = json.dumps(t, sort_keys=True)
            elif isinstance(t, str):
                try:
                    t_parsed = json.loads(t)
                    if isinstance(t_parsed, list):
                        t_parsed = json.dumps(t_parsed, sort_keys=True)
                    else:
                        t_parsed = t
                except:
                    t_parsed = t
            else:
                t_parsed = str(t)
            tag_counts[t_parsed] = tag_counts.get(t_parsed, 0) + 1

    # Get top 5 tags
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tags_list = [tag for tag, count in top_tags]

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 6
    total_fanfics = len(filtered_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = filtered_fanfics[start:end]

    return render_template(
        "index.html",
        fanfics=display_fanfics,
        all_tags=sorted(all_tags),
        top_tags=top_tags_list,
        current_tag=tag,
        search=request.args.get("search", ""),
        author=request.args.get("author", ""),
        logged_in=logged_in(),
        current_page=page,
        total_pages=total_pages,
        tags=site_info,
        site_info=site_info,
        is_admin=is_admin(),
        show_back_link=True,
        latest_post=latest_post,
    )


## above is actually refactored

ALLOWED_USERNAMES = [
    "cammy",
    "offiz",
    "seal",
    "moonajauna",
    "fizzypoppeaches",
    "yuri",
    "chimerathing",
    "yuri",
]  # your list of allowed usernames


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if username is in allowed list
        if username not in ALLOWED_USERNAMES:
            abort(403)

        # Check if username exists in the database
        existing_user = get_user(username)
        if existing_user:
            abort(400)

        # Hash the password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # Get current IP
        ip_address = request.remote_addr

        # Prepare user data
        user_data = {
            "username": username,
            "password": hashed_password,
            "is_admin": False,
            "bio": "",
            "pfp": "",
            "custom_css": "",
            "display_name": "",
            "ip": ip_address,
        }

        # Save new user to database
        create_user(user_data)

        # Log the IP (optional)
        log_ip(username=session.get("username"), page=request.path)

        # Log the user in
        session["username"] = username

        return redirect(url_for("index"))

    # For GET, render registration form
    return render_template(
        "register.html",
        user=session.get("username"),
        is_admin=is_admin(),
        username="",
        session=session,
        logged_in=logged_in(),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    username = ""
    user = None
    admin_status = False
    logged_in = False

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user(username)  # fetch user from database

        print("Fetched user:", user)  # debug print

        if not user:
            abort(404)

        # check if user is banned
        if user.get("banned"):
            abort(403)

        # retrieve the stored hashed password
        stored_hashed = user.get("password")  # stored as string

        # verify password with bcrypt
        if bcrypt.checkpw(password.encode("utf-8"), stored_hashed.encode("utf-8")):
            # password is correct

            # get current ip
            ip_address = request.remote_addr

            # log the ip in the audit log
            log_ip(username=session.get("username"), page=request.path)

            # update the user's ip in the database
            # Assuming your user table has an 'ip' column
            conn = get_db_connection()
            conn.execute(
                "UPDATE users SET ip = ? WHERE username = ?", (ip_address, username)
            )
            conn.commit()
            conn.close()

            # set session variables
            session["username"] = username
            session["is_admin"] = user.get("is_admin", False)

            print("Session 'is_admin' set to:", session["is_admin"])  # debug

            return redirect(url_for("index"))
        else:
            return "Invalid credentials"

    # for GET request
    logged_in = "username" in session
    if logged_in:
        username = session["username"]
        user = get_user(username)
        admin_status = session.get("is_admin", False)

    return render_template(
        "login.html",
        username=username,
        session=session,
        logged_in=logged_in,
        user=user,
        is_admin=admin_status,
    )


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


@app.route("/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic(fic_id):
    # Delete the fanfic from the database
    conn = get_db_connection()
    conn.execute("DELETE FROM fanfics WHERE id = ?", (fic_id,))
    conn.commit()
    conn.close()

    conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fic_id,))
    conn.commit()

    return redirect(url_for("profile"))


@app.route("/add_tag", methods=["POST"])
def add_tag():
    # get the tag from JSON request
    data_in = request.get_json()
    new_tag = data_in.get("tag", "").strip()

    if not new_tag:
        return jsonify({"success": False, "error": "No tag provided"}), 400

    # Check if the tag already exists in the database
    conn = get_db_connection()
    existing = conn.execute("SELECT 1 FROM tags WHERE name = ?", (new_tag,)).fetchone()

    if existing:
        conn.close()
        return jsonify({"success": True, "message": "Tag already exists"})

    # Insert the new tag
    conn.execute("INSERT INTO tags (name) VALUES (?)", (new_tag,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "tag": new_tag})


@app.route("/profile/<username>")
def user_profile(username):
    # Fetch user details from the database
    user = get_user(username)
    if not user:
        abort(404)

    user["username"] = username

    # Check if the current logged-in user is the owner
    is_owner = username == session.get("username")
    logged_in = "username" in session
    admin_status = is_admin()

    # Fetch fanfics owned by the user from the database
    conn = get_db_connection()
    fanfics_rows = conn.execute(
        "SELECT * FROM fanfics WHERE owner = ?", (username,)
    ).fetchall()
    conn.close()

    # Convert to list of dicts
    fanfics = [dict(row) for row in fanfics_rows]

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 3
    total_fanfics = len(fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = fanfics[start:end]

    return render_template(
        "profile.html",
        fanfics=display_fanfics,
        username=username,
        session=session,
        logged_in=logged_in,
        user=user,
        is_owner=is_owner,
        is_admin=admin_status,
        current_page=page,
        total_pages=total_pages,
    )


@app.route("/profile")
def profile():
    if not logged_in():
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user(username)
    if not user:
        abort(404)

    # Log IP
    log_ip(username=username, page=request.path)

    # Fetch fanfics owned by the user from the database
    conn = get_db_connection()
    fanfics_rows = conn.execute(
        "SELECT * FROM fanfics WHERE owner = ?", (username,)
    ).fetchall()
    conn.close()

    fanfics = [dict(row) for row in fanfics_rows]

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 3
    total_fanfics = len(fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = fanfics[start:end]

    # Assuming notes are stored in the database, fetch notes if needed
    # For now, using placeholder
    notes_data = {}  # Replace with actual database fetch if applicable

    return render_template(
        "profile.html",
        fanfics=display_fanfics,
        notes=notes_data,
        username=username,
        session=session,
        logged_in=True,
        user=user,
        is_owner=True,  # Since this is your profile page
        is_admin=is_admin(),
        current_page=page,
        total_pages=total_pages,
    )


@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        return redirect(url_for("login"))

    old_username = session["username"]
    user = get_user(old_username)
    if not user:
        abort(404)

    if request.method == "POST":
        # Get form data safely
        username_input = request.form.get("username")
        new_username = username_input.strip() if username_input else old_username
        new_bio_raw = request.form.get("bio", "")
        pfp_file = request.files.get("pfp")
        new_custom_css = request.form.get("custom_css")
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        # Verify current password before changing
        if new_password:
            stored_hash = user.get("password", "")
            if not stored_hash:
                abort(403)  # No valid password stored

            # Verify using bcrypt
            if not bcrypt.checkpw(
                current_password.encode("utf-8"), stored_hash.encode("utf-8")
            ):
                abort(403)

        # Sanitize bio
        new_bio = sanitize_bio(new_bio_raw.strip())

        # Handle profile picture upload
        if pfp_file and pfp_file.filename != "":
            filename = secure_filename(pfp_file.filename)
            upload_dir = os.path.join(app.static_folder, "pfps")
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)
            print("Saving file to:", upload_path)
            pfp_file.save(upload_path)
            user["pfp"] = f"pfps/{filename}"

        # Update username if changed
        if new_username != old_username:
            if get_user(new_username):
                abort(400)
            # Update user in database
            update_user(
                {
                    "username": new_username,
                    "bio": new_bio,
                    "custom_css": new_custom_css,
                    "pfp": user.get("pfp", ""),
                }
            )
            # Update session
            session["username"] = new_username

            # Update fanfics owned/authored
            conn = get_db_connection()
            conn.execute(
                "UPDATE fanfics SET owner = ?, author = ? WHERE owner = ?",
                (new_username, new_username, old_username),
            )
            conn.commit()
            conn.close()
        else:
            # Update user info without changing username
            user["bio"] = new_bio
            user["custom_css"] = new_custom_css

        # Handle password change
        if new_password:
            # Hash with bcrypt
            hashed_password = bcrypt.hashpw(
                new_password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            update_user_password(user["username"], hashed_password)
        else:
            # No password change, just update user info
            update_user(user)

        return redirect(url_for("profile"))

    return render_template(
        "edit_profile.html",
        user=user,
        is_admin=is_admin(),
        username=old_username,
        session=session,
        is_owner=True,
        logged_in=True,
    )


###### yuh


@app.route("/submit", methods=["GET", "POST"])
def submit():
    if not logged_in():
        return redirect(url_for("login"))

    log_ip(username=session.get("username"), page=request.path)

    # Fetch all tags for display
    conn = get_db_connection()
    all_tags_rows = conn.execute("SELECT name FROM tags").fetchall()

    # Prepare tag list
    all_tags = [row["name"] for row in all_tags_rows]

    if request.method == "POST":
        # Generate new fanfic ID
        max_id_row = conn.execute("SELECT MAX(id) FROM fanfics").fetchone()
        new_id = (max_id_row[0] or 0) + 1

        # Collect chapters
        chapters = []
        pattern_title = re.compile(r"chapter_title_(\d+)")
        for key in request.form:
            match = pattern_title.match(key)
            if match:
                index = match.group(1)
                title = request.form.get(f"chapter_title_{index}")
                content = request.form.get(f"chapter_content_{index}")
                if title or content:
                    content = re.sub(r"\n+", "\n", content.strip()) if content else ""
                    chapters.append({"title": title, "content": content})

        print("Collected chapters:", chapters)

        # Get and process tags
        selected_tags = request.form.getlist("tags")
        new_tag = request.form.get("new_tag", "").strip()

        combined_tags = list(set(selected_tags))
        if new_tag:
            combined_tags.append(new_tag)

        age_rating = request.form.get("age_rating")

        # Insert into fanfics table (without chapters)
        conn.execute(
            """
            INSERT INTO fanfics (
                id, title, author, owner, fandom, comments, kudos, age_rating
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id,
                request.form["title"],
                session["username"],
                session["username"],
                request.form["fandom"],
                json.dumps([]),  # comments
                json.dumps([]),  # kudos
                age_rating,
            ),
        )
        conn.commit()

        # Insert chapters into chapters table
        for index, chapter in enumerate(chapters):
            conn.execute(
                "INSERT INTO chapters (fanfic_id, id, title, content) VALUES (?, ?, ?, ?)",
                (new_id, index + 1, chapter["title"], chapter["content"]),
            )

        # Insert tags into tags and associate with fanfic
        for tag in combined_tags:
            conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            tag_id_row = conn.execute(
                "SELECT id FROM tags WHERE name = ?", (tag,)
            ).fetchone()
            if tag_id_row:
                tag_id = tag_id_row["id"]
                conn.execute(
                    "INSERT INTO fanfic_tags (fanfic_id, tag_id) VALUES (?, ?)",
                    (new_id, tag_id),
                )

        conn.commit()
        conn.close()

        print("New fanfic added with chapters:", chapters)
        return redirect(url_for("view_fic", fid=new_id))

    # For GET, render the form
    return render_template(
        "fanfic/submit.html",
        logged_in=True,
        tags=all_tags,
        is_admin=is_admin(),
    )


@app.route("/fic/<int:fid>")
def view_fic(fid):
    conn = get_db_connection()

    # Fetch the main fanfic record
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # Parse comments
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # Deduplicate comments
    unique_comments = []
    seen = set()
    for c in comments:
        key = (c["name"], c["content"])
        if key not in seen:
            seen.add(key)
            unique_comments.append(c)
    fanfic["comments"] = unique_comments

    # Parse kudos (assuming stored as JSON array of usernames)
    kudos_json = fanfic.get("kudos")
    if kudos_json:
        try:
            kudos_list = json.loads(kudos_json)
        except json.JSONDecodeError:
            kudos_list = []
    else:
        kudos_list = []

    # Deduplicate kudos
    kudos = list(set(kudos_list))

    # Fetch chapters
    chapters_rows = conn.execute(
        "SELECT * FROM chapters WHERE fanfic_id = ?", (fid,)
    ).fetchall()

    # Fetch tags
    tags_rows = conn.execute(
        "SELECT t.name FROM tags t JOIN fanfic_tags ft ON t.id = ft.tag_id WHERE ft.fanfic_id = ?",
        (fid,),
    ).fetchall()

    # Close the connection after all queries
    conn.close()

    # Process chapters content
    chapters = [dict(c) for c in chapters_rows] if chapters_rows else []
    for chapter in chapters:
        if "content" in chapter:
            chapter["content"] = re.sub(
                r"^\s+", "", chapter["content"], flags=re.MULTILINE
            ).strip()
            chapter["content"] = re.sub(r"\n\s*\n+", "\n\n", chapter["content"])

    # Extract tag names
    tags = [row["name"] for row in tags_rows]

    # Attach tags to fanfic dict for template access
    fanfic["tags"] = tags

    # Check user session and get admin status safely
    user = get_user(session.get("username", ""))
    is_admin = user.get("is_admin", False) if user else False

    # Pass to template
    return render_template(
        "fanfic/view_fic.html",
        fic=fanfic,
        chapters=chapters,
        kudos=kudos,
        logged_in=("username" in session),
        is_admin=is_admin,
    )


@app.route("/edit/<int:fid>", methods=["GET", "POST"])
def edit_fic(fid):
    # Fetch the fanfic from the database
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        return "Fanfic not found"

    # Check ownership and login
    if not logged_in() or fanfic_row["owner"] != session["username"]:
        conn.close()
        return "Unauthorized"

    # Fetch all tags for display
    all_tags_rows = conn.execute("SELECT name FROM tags").fetchall()
    all_tags = [row["name"] for row in all_tags_rows]

    # Fetch chapters
    chapters_rows = conn.execute(
        "SELECT * FROM chapters WHERE fanfic_id = ? ORDER BY id", (fid,)
    ).fetchall()
    chapters = [dict(c) for c in chapters_rows]

    # Fetch tags associated with this fanfic
    tags_rows = conn.execute(
        "SELECT t.name FROM tags t JOIN fanfic_tags ft ON t.id = ft.tag_id WHERE ft.fanfic_id = ?",
        (fid,),
    ).fetchall()
    current_tags = [row["name"] for row in tags_rows]

    # Parse comments JSON
    comments_json = fanfic_row["comments"]
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # Parse kudos JSON
    kudos_json = fanfic_row["kudos"]
    if kudos_json:
        try:
            kudos = json.loads(kudos_json)
        except json.JSONDecodeError:
            kudos = []
    else:
        kudos = []

    # Handle POST request for updating fanfic
    if request.method == "POST":
        # Parse tags from the form's hidden input (comma-separated string)
        tags_str = request.form.get("tags", "")
        selected_tags = [tag.strip() for tag in tags_str.split(",") if tag.strip()]

        # Handle optional new tag input
        new_tag = request.form.get("new_tag", "").strip()
        if new_tag:
            selected_tags.append(new_tag)

        # Deduplicate tags
        updated_tags = list(set(selected_tags))

        # Collect chapters
        chapters = []
        pattern_title = re.compile(r"chapter_title_(\d+)")
        for key in request.form:
            match = pattern_title.match(key)
            if match:
                index = match.group(1)
                title = request.form.get(f"chapter_title_{index}")
                content = request.form.get(f"chapter_content_{index}")
                if title or content:
                    content = re.sub(r"\n+", "\n", content.strip()) if content else ""
                    chapters.append({"title": title, "content": content})

        # Update main fanfic fields
        conn.execute(
            "UPDATE fanfics SET title=?, fandom=?, age_rating=? WHERE id=?",
            (
                request.form["title"],
                request.form["fandom"],
                request.form.get("age_rating", "13+"),
                fid,
            ),
        )

        # Update chapters: delete existing and insert new
        conn.execute("DELETE FROM chapters WHERE fanfic_id = ?", (fid,))
        for index, chapter in enumerate(chapters):
            # Remove 'id' from insert, since it's autoincrement
            conn.execute(
                "INSERT INTO chapters (fanfic_id, title, content) VALUES (?, ?, ?)",
                (fid, chapter["title"], chapter["content"]),
            )

        # Update tags: clear old associations
        conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fid,))

        # Insert tags and create associations
        for tag in updated_tags:
            # Insert new tag if it doesn't exist
            conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            # Retrieve the tag id
            tag_id_row = conn.execute(
                "SELECT id FROM tags WHERE name = ?", (tag,)
            ).fetchone()
            if tag_id_row:
                conn.execute(
                    "INSERT INTO fanfic_tags (fanfic_id, tag_id) VALUES (?, ?)",
                    (fid, tag_id_row["id"]),
                )

        # Save comments and kudos if needed (not shown here, keep your logic)

        conn.commit()
        conn.close()
        return redirect(url_for("view_fic", fid=fid))

    conn.close()

    # Render edit form with current data
    return render_template(
        "fanfic/edit_fic.html",
        fic={
            "id": fid,
            "title": fanfic_row["title"],
            "fandom": fanfic_row["fandom"],
            "age_rating": fanfic_row["age_rating"],
            "comments": comments,
            "kudos": kudos,
            "owner": fanfic_row["owner"],
            "tags": current_tags,
            "chapters": chapters,
        },
        all_tags=all_tags,
        logged_in=logged_in(),
        is_owner=True,
        is_admin=is_admin(),
    )


@app.route("/kudo/<int:fid>", methods=["POST"])
def add_kudo(fid):
    if not logged_in():
        return redirect(url_for("login"))

    # Connect to the database
    conn = get_db_connection()

    # Fetch the fanfic record
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # Parse current kudos
    kudos_json = fanfic.get("kudos")
    if kudos_json:
        try:
            kudos_list = json.loads(kudos_json)
        except json.JSONDecodeError:
            kudos_list = []
    else:
        kudos_list = []

    user = session["username"]
    if user not in kudos_list:
        kudos_list.append(user)

        # Save updated kudos back to the database
        updated_kudos_json = json.dumps(kudos_list)
        conn.execute(
            "UPDATE fanfics SET kudos = ? WHERE id = ?", (updated_kudos_json, fid)
        )
        conn.commit()

        # Log IP
        log_ip(username=user, page=request.path)

    conn.close()

    return redirect(url_for("view_fic", fid=fid))


def user_exists(username):
    return username in data["users"]


def linkify_mentions(content):
    def replace_mention(match):
        username = match.group(1)
        if user_exists(username):
            return f'<a href="{url_for("profile", username=username)}">@{username}</a>'
        else:
            return f"@{username}"

    pattern = r"@(\w+)"  #  adjust pattern with special chars
    return re.sub(pattern, replace_mention, content)


@app.route("/comment/<int:fid>", methods=["POST"])
def add_comment(fid):
    if not logged_in():
        return redirect(url_for("login"))

    # Fetch current fanfic record
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # Parse existing comments JSON
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # Prepare new comment
    content = request.form["content"]
    content_with_links = linkify_mentions(content)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = session["username"]
    user = get_user(username)  # assuming you have this function
    pfp_path = user["pfp"] if user and "pfp" in user else ""

    new_comment = {
        "name": username,
        "content": content_with_links,
        "timestamp": timestamp,
        "pfp": pfp_path,
        "user": user,  # optional, if you want to store full user info
    }

    # Append new comment
    comments.append(new_comment)

    # Save updated comments JSON back to the database
    updated_comments_json = json.dumps(comments)
    conn.execute(
        "UPDATE fanfics SET comments = ? WHERE id = ?", (updated_comments_json, fid)
    )
    conn.commit()
    conn.close()

    log_ip(username=username, page=request.path)
    return redirect(url_for("view_fic", fid=fid))


@app.route("/delete_comment/<int:fid>/<int:comment_index>", methods=["POST"])
def delete_comment(fid, comment_index):
    if not logged_in():
        return redirect(url_for("login"))

    # Fetch the fanfic from database
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        return "Fanfic not found"

    fanfic = dict(fanfic_row)

    # Decode comments JSON
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # Validate index
    if comment_index < 0 or comment_index >= len(comments):
        conn.close()
        abort(404)

    comment = comments[comment_index]
    current_user = session.get("username")
    is_admin = session.get("is_admin", False)

    # Check permissions
    if comment["name"] != current_user and not is_admin:
        conn.close()
        abort(403)

    # Remove comment
    comments.pop(comment_index)

    # Save updated comments json back to database
    updated_comments_json = json.dumps(comments)
    conn.execute(
        "UPDATE fanfics SET comments = ? WHERE id = ?", (updated_comments_json, fid)
    )
    conn.commit()
    conn.close()

    # Log deletion
    log_ip(username=current_user, page=request.path)

    return redirect(url_for("view_fic", fid=fid))


# fully refactored above


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    current_ip = request.remote_addr

    # Check if IP is banned
    if is_ip_banned(current_ip):
        abort(403)

    # Check user session and admin status
    username = session.get("username")
    if not username:
        abort(404)

    user = get_user(username)
    if not user or not user.get("is_admin"):
        abort(403)

    # Log access
    log_ip(username=username, page=request.path)

    # Handle banning IP via POST
    if request.method == "POST":
        ip_to_ban = request.form.get("ip")
        if ip_to_ban:
            save_banned_ip(ip_to_ban)
            return f"IP {ip_to_ban} has been banned.", 200

    # Fetch all users from DB
    users = get_all_users()
    user_ips = {u["username"]: u.get("ip", "Unknown") for u in users}

    # Fetch fanfics (assumes get_fanfics() is DB-based)
    fanfics = get_fanfics()

    return render_template(
        "admin/admin.html",
        fanfics=fanfics,
        is_admin=True,
        user=user,
        username=username,
        session=session,
        logged_in=True,
        user_ips=user_ips,
        users=users,
    )


@app.route("/admin/delete_user/<username>", methods=["POST"])
def delete_user(username):
    if not is_admin():
        abort(403)

    # Fetch user from database
    user = get_user(username)
    if not user:
        abort(404)

    # Delete user from database
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    except Exception as e:
        # Log error if needed
        return f"Error deleting user: {str(e)}", 500
    finally:
        conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic_admin(fic_id):
    if not is_admin():
        return "Access Denied", 403

    conn = get_db_connection()
    try:
        # Check if fanfic exists
        fanfic = conn.execute(
            "SELECT * FROM fanfics WHERE id = ?", (fic_id,)
        ).fetchone()
        if not fanfic:
            abort(404)

        # Delete fanfic
        conn.execute("DELETE FROM fanfics WHERE id = ?", (fic_id,))
        # Also delete associated chapters, tags, etc., if applicable
        conn.execute("DELETE FROM chapters WHERE fanfic_id = ?", (fic_id,))
        conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fic_id,))
        # Commit changes
        conn.commit()
    except Exception as e:
        return f"Error deleting fanfic: {str(e)}", 500
    finally:
        conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/ban_ip", methods=["POST"])
def ban_ip():
    if not is_admin():
        abort(403)

    ip_to_ban = request.form["ip"]
    if is_ip_banned(ip_to_ban):
        # If already banned, unban it
        unban_ip(ip_to_ban)
        return f"IP {ip_to_ban} has been unbanned."
    else:
        # Otherwise, ban it
        save_banned_ip(ip_to_ban)
        return f"IP {ip_to_ban} has been banned."


@app.route("/admin/set_display_name/<username>", methods=["GET", "POST"])
def set_display_name(username):
    if not is_admin():
        abort(404)

    user = get_user(username)
    if not user:
        abort(404)

    if request.method == "POST":
        new_display_name = request.form.get("display_name", "").strip()
        if not new_display_name:
            error = "Please enter a display name."
            return render_template(
                "admin/set_display_name.html", user=user, error=error
            )

        # Only allow admins to set display names for users
        if user.get("is_admin"):
            # Update display_name in the database directly
            conn = get_db_connection()
            conn.execute(
                "UPDATE users SET display_name = ? WHERE username = ?",
                (new_display_name, username),
            )
            conn.commit()
            conn.close()

            return redirect(url_for("profile", username=username))
        else:
            abort(403)

    # For GET request, ensure display_name exists in the database
    if not user.get("display_name"):
        # Optionally, set display_name to username if not set
        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET display_name = ? WHERE username = ?",
            (user["username"], username),
        )
        conn.commit()
        conn.close()

        # Re-fetch user if needed
        user = get_user(username)

    return render_template(
        "admin/set_display_name.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/notes")
def notes():
    if not logged_in():
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user(username)
    if not user:
        abort(404)

    log_ip(username=username, page=request.path)

    # Connect to DB
    conn = get_db_connection()
    cursor = conn.cursor()

    # Count total notes for pagination
    total_notes = cursor.execute(
        "SELECT COUNT(*) FROM notes WHERE owner = ?", (username,)
    ).fetchone()[0]

    # Pagination setup
    page = int(request.args.get("page", 1))
    per_page = 10
    total_pages = (total_notes + per_page - 1) // per_page
    start = (page - 1) * per_page

    # Fetch notes for the current page
    cursor.execute(
        "SELECT id, content FROM notes WHERE owner = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (username, per_page, start),
    )

    notes_rows = cursor.fetchall()
    conn.close()

    # Format notes
    notes_with_ids = [
        {"id": row["id"], "content": row["content"]} for row in notes_rows
    ]

    return render_template(
        "notes/notes.html",
        notes=notes_with_ids,
        username=username,
        session=session,
        logged_in=True,
        user=user,
        is_owner=True,
        is_admin=is_admin(),
        current_page=page,
        total_pages=total_pages,
    )


@app.route("/notes/<note_id>")
def view_note(note_id):
    if not logged_in():
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user(username)
    if not user:
        abort(404)

    # Connect to DB
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the note by id
    cursor.execute("SELECT owner, content FROM notes WHERE id = ?", (note_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    owner = row["owner"]
    content = row["content"]

    # Authorization check: only owner can view
    if owner != username:
        abort(403)

    # If content is JSON, decode it
    try:
        note_data = json.loads(content)
        # If note_data is a dict with 'content', extract it
        if isinstance(note_data, dict) and "content" in note_data:
            display_content = note_data["content"]
        else:
            display_content = content
    except json.JSONDecodeError:
        display_content = content

    return render_template(
        "notes/view_note.html",
        note_id=note_id,
        note_content=display_content,
        user=user,
        logged_in=True,
        session=session,
        is_owner=True,
        is_admin=is_admin(),
    )


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    if not logged_in():
        return redirect(url_for("login"))

    username = session.get("username")
    user = get_user(username) if username else None

    if request.method == "POST":
        log_ip(username=username, page=request.path)

        content = request.form["content"]
        sanitized_content = sanitize_note_content(content)

        # Insert into database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (owner, content) VALUES (?, ?)",
            (username, sanitized_content),
        )
        conn.commit()

        # Get the new note's id
        note_id = cursor.lastrowid
        conn.close()

        return redirect(url_for("view_note", note_id=note_id))
    return render_template(
        "notes/new_note.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/notes/<note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    # Fetch the note from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT owner, content FROM notes WHERE id = ?", (note_id,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        print(f"Note with ID {note_id} not found.")
        abort(404)

    owner = row["owner"]
    content = row["content"]
    current_user = session.get("username")

    # Check ownership
    if owner != current_user:
        conn.close()
        print(f"User {current_user} unauthorized to edit note {note_id}")
        abort(403)

    log_ip(username=current_user, page=request.path)

    if request.method == "POST":
        if request.form.get("delete"):
            # Delete the note
            cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            conn.commit()
            conn.close()
            return redirect(url_for("notes"))
        else:
            new_content = request.form.get("content")
            if not new_content:
                conn.close()
                return render_template(
                    "notes/edit_note.html",
                    content=content,
                    note_id=note_id,
                    error="Content cannot be empty",
                    delete_button=False,
                    is_admin=is_admin(),
                    logged_in=logged_in(),
                )

            sanitized_content = sanitize_note_content(new_content)
            cursor.execute(
                "UPDATE notes SET content = ? WHERE id = ?",
                (sanitized_content, note_id),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("view_note", note_id=note_id))
    else:
        conn.close()
        return render_template(
            "notes/edit_note.html",
            content=content,
            note_id=note_id,
            delete_button=False,
            is_admin=is_admin(),
            logged_in=logged_in(),
        )


@app.route("/blog")
def blog():
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all blog posts with authors
    cursor.execute("""
        SELECT bp.id, bp.title, bp.content, bp.timestamp, u.display_name, bp.author
        FROM blog_posts bp
        LEFT JOIN users u ON bp.author = u.username
    """)
    posts_rows = cursor.fetchall()
    conn.close()

    # Prepare posts list
    posts = []
    for row in posts_rows:
        # Safely get 'display_name'
        display_name = (
            row["display_name"]
            if "display_name" in row and row["display_name"]
            else None
        )
        # Safely get 'author'
        author_value = row["author"] if "author" in row else ""

        # Fallback for author display
        author_display = display_name if display_name else author_value
        timestamp_str = row["timestamp"]
        try:
            formatted_time = datetime.fromisoformat(timestamp_str).strftime(
                "%B %d, %Y at %I:%M %p"
            )
        except Exception:
            formatted_time = timestamp_str  # fallback if parsing fails

        posts.append(
            {
                "id": row["id"],
                "title": row["title"],
                "content": row["content"],
                "author": author_display,
                "timestamp": timestamp_str,
                "formatted_timestamp": formatted_time,
            }
        )

    # Sort posts by timestamp descending
    posts.sort(key=lambda x: x["timestamp"], reverse=True)
    print(f"Number of posts in list: {len(posts)}")

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 6
    total_posts = len(posts)
    total_pages = (total_posts + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_posts = posts[start:end]

    return render_template(
        "blog.html",
        posts=display_posts,
        is_admin=is_admin(),
        logged_in=logged_in(),
        current_page=page,
        total_pages=total_pages,
    )

    # Sort posts by timestamp descending
    posts.sort(key=lambda x: x["timestamp"], reverse=True)
    print(f"Number of posts in list: {len(posts)}")

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 6
    total_posts = len(posts)
    total_pages = (total_posts + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_posts = posts[start:end]

    return render_template(
        "blog.html",
        posts=display_posts,
        is_admin=is_admin(),
        logged_in=logged_in(),
        current_page=page,
        total_pages=total_pages,
    )


@app.route("/blog/<post_id>")
def view_blog_post(post_id):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the post along with author display name
    cursor.execute(
        """
        SELECT bp.id, bp.title, bp.content, bp.timestamp, u.display_name, bp.author
        FROM blog_posts bp
        LEFT JOIN users u ON bp.author = u.username
        WHERE bp.id = ?
        """,
        (post_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    # Safely get display_name; fallback to 'author' if missing
    display_name = (
        row["display_name"]
        if "display_name" in row.keys() and row["display_name"]
        else None
    )
    author_value = row["author"] if "author" in row.keys() else ""

    author_display = display_name if display_name else author_value

    # Prepare post data
    post = {
        "id": row["id"],
        "title": row["title"],
        "content": row["content"],
        "timestamp": row["timestamp"],
        "author": author_display,
    }

    # Format timestamp
    try:
        post["formatted_timestamp"] = datetime.fromisoformat(
            post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")
    except Exception:
        post["formatted_timestamp"] = post["timestamp"]  # fallback

    return render_template(
        "view_blog_post.html",
        post=post,
        post_id=post_id,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/blog/new", methods=["GET", "POST"])
def new_blog_post():
    if not logged_in():
        return redirect(url_for("login"))

    username = session.get("username")
    user = get_user(username) if username else None

    # Check if user is admin
    if not user or not user.get("is_admin", False):
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        display_name = user.get("display_name", username)

        # Insert new post into database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO blog_posts (title, content, author, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (title, content, display_name, datetime.now().isoformat()),
        )
        conn.commit()
        post_id = cursor.lastrowid
        conn.close()

        return redirect(url_for("view_blog_post", post_id=post_id))
    return render_template(
        "admin/new_blog_post.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/blog/<post_id>/edit", methods=["GET", "POST"])
def edit_blog_post(post_id):
    # Fetch the post from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, content, author, timestamp FROM blog_posts WHERE id = ?",
        (post_id,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(404)

    # Check if user is admin
    username = session.get("username")
    user = get_user(username) if username else None

    if not user or not user.get("is_admin", False):
        conn.close()
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        timestamp = datetime.now().isoformat()

        # Update the post in the database
        cursor.execute(
            """
            UPDATE blog_posts
            SET title = ?, content = ?, timestamp = ?
            WHERE id = ?
            """,
            (title, content, timestamp, post_id),
        )
        conn.commit()
        conn.close()

        return redirect(url_for("view_blog_post", post_id=post_id))
    else:
        # Render the edit form with the current post data
        conn.close()
        return render_template(
            "admin/edit_blog_post.html",
            post=row,
            post_id=post_id,
            is_admin=is_admin(),
            logged_in=logged_in(),
        )


# i kinda give up on comments sorry
@app.route("/blog/<post_id>/delete", methods=["POST"])
def delete_blog_post(post_id):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the post exists
    cursor.execute("SELECT id FROM blog_posts WHERE id = ?", (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        abort(404)

    # Check admin permissions
    username = session.get("username")
    user = get_user(username) if username else None
    if not user or not user.get("is_admin", False):
        conn.close()
        abort(403)

    # Delete the post
    cursor.execute("DELETE FROM blog_posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("blog"))


@app.route("/about")
def about():
    # Fetch site info from database or set defaults
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT title, content FROM site_info")
    site_info = cursor.fetchone()
    conn.close()

    # Prepare data for template
    if site_info:
        current_info = {"title": site_info["title"], "content": site_info["content"]}
    else:
        current_info = {"title": "Default Title", "content": "Default Content"}

    return render_template("about.html", site_info=current_info)


@app.route("/admin/site-info", methods=["GET", "POST"])
def edit_site_info():
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        # Get updated info from form
        title = request.form.get("title")
        content = request.form.get("content")

        # Check if site info exists
        cursor.execute("SELECT * FROM site_info")
        existing = cursor.fetchone()

        if existing:
            # Update existing record
            cursor.execute(
                "UPDATE site_info SET title = ?, content = ?", (title, content)
            )
        else:
            # Insert new record if not exists
            cursor.execute(
                "INSERT INTO site_info (title, content) VALUES (?, ?)", (title, content)
            )

        conn.commit()
        conn.close()
        return redirect(url_for("about"))

    # For GET, fetch current site info
    cursor.execute("SELECT title, content FROM site_info")
    site_info = cursor.fetchone()
    conn.close()

    # Prepare data for template
    if site_info:
        current_info = {"title": site_info["title"], "content": site_info["content"]}
    else:
        current_info = {"title": "", "content": ""}

    return render_template(
        "admin/edit_site_info.html",
        site_info=current_info,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.template_filter("format_datetime")
def format_datetime(value):
    dt = datetime.fromisoformat(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


@app.route("/admin/logs")
def show_logs():
    username = session.get("username")
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all users
    cursor.execute("SELECT username FROM users")
    users_list = [row["username"] for row in cursor.fetchall()]

    # Fetch IP logs
    cursor.execute("SELECT * FROM ip_logs ORDER BY timestamp DESC")
    ip_logs = cursor.fetchall()

    conn.close()

    return render_template(
        "admin/logs.html",
        logs=ip_logs,
        user_logs=user_logs,
        username=username,
        users=users_list,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/all_logs")
def all_logs():
    # Pagination parameters
    per_page = 20
    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch total count to calculate total pages
    cursor.execute("SELECT COUNT(*) FROM ip_logs")
    total_count = cursor.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page  # ceiling division

    # Fetch logs for current page
    cursor.execute(
        "SELECT username, ip, timestamp, page FROM ip_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    )
    logs_rows = cursor.fetchall()

    # Convert to list of dicts
    all_logs = [
        {
            "username": row["username"],
            "ip": row["ip"],
            "timestamp": row["timestamp"],
            "page": row["page"],
        }
        for row in logs_rows
    ]

    conn.close()

    return render_template(
        "admin/all_logs.html",
        logs=all_logs,
        current_page=page,
        total_pages=total_pages,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/logs/<username>")
def user_logs(username):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all users for the dropdown/navigation
    cursor.execute("SELECT username FROM users")
    users = [row["username"] for row in cursor.fetchall()]

    # Fetch IP logs for the specific user
    cursor.execute(
        "SELECT ip, timestamp, page FROM ip_logs WHERE username = ? ORDER BY timestamp DESC",
        (username,),
    )
    logs = cursor.fetchall()

    # Convert logs to list of dicts for easier use in template
    user_logs_list = [
        {"ip": row["ip"], "timestamp": row["timestamp"], "page": row["page"]}
        for row in logs
    ]

    conn.close()

    return render_template(
        "admin/user_logs.html",
        user_logs=user_logs_list,
        username=username,
        users=users,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.template_filter("nl2br")
def nl2br_filter(s):
    if s is None:
        return ""
    return s.replace("\n", "<br>\n")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
