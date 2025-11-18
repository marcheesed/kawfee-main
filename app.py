import ast
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta
from typing import Any

import bcrypt
import bleach
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from jinja2 import pass_environment
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

#######################################
#                                     #
#            KAWFEE 1.25              #
#            @marcheesed              #
#                                     #
# #####################################


def get_db_connection():
    conn = sqlite3.connect("kawfee.db", check_same_thread=False)
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

# remember to update when policy updates
CURRENT_POLICY_VERSION = 3

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


def generate_invite_code():
    return secrets.token_urlsafe(16)  # 16 bytes URL-safe token


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        # x-forwarded-for can contain multiple ips so we'll be taking the first one
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    elif request.headers.get("X-Real-IP"):
        ip = request.headers.get("X-Real-IP")
    else:
        ip = request.remote_addr
    return ip


def update_user_ip(username):
    ip = get_client_ip()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET ip = ? WHERE username = ?",
            (ip, username),
        )
        conn.commit()
    finally:
        conn.close()


def log_ip(username=None, page=None):
    ip = get_client_ip()
    now = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if username:
            # check existing log
            cursor.execute(
                """
                SELECT * FROM ip_logs
                WHERE ip = ? AND username = ? AND timestamp > ?
                """,
                (ip, username, (datetime.now() - timedelta(minutes=10)).isoformat()),
            )
            existing_log = cursor.fetchone()

            if existing_log:
                # update timestamp
                execute_with_retry(
                    cursor,
                    """
                    UPDATE ip_logs SET timestamp = ?, page = ? WHERE id = ?
                """,
                    (now, page, existing_log["id"]),
                )
            else:
                # insert new log
                execute_with_retry(
                    cursor,
                    """
                    INSERT INTO ip_logs (ip, timestamp, username, page)
                    VALUES (?, ?, ?, ?)
                """,
                    (ip, now, username, page),
                )
        else:
            # log anonymous user
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
    # check if ip already exists to prevent duplicates
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


def get_user_invite_code(username, bypass_limit=False):
    today_str = date.today().isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if there's an invite code for today
    cursor.execute(
        "SELECT invite_code, date FROM user_invite_codes WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()

    # If bypass_limit is True, always generate a new code
    if bypass_limit:
        invite_code = generate_invite_code()
        # Save or update record
        if row:
            cursor.execute(
                "UPDATE user_invite_codes SET invite_code = ?, date = ? WHERE username = ?",
                (invite_code, today_str, username),
            )
        else:
            cursor.execute(
                "INSERT INTO user_invite_codes (username, invite_code, date) VALUES (?, ?, ?)",
                (username, invite_code, today_str),
            )
        conn.commit()
        conn.close()
        return invite_code

    # Normal behavior: only generate new code if no code for today
    if row and row["date"] == today_str:
        invite_code = row["invite_code"]
    else:
        # Generate new code
        invite_code = generate_invite_code()
        # Save or update record
        if row:
            cursor.execute(
                "UPDATE user_invite_codes SET invite_code = ?, date = ? WHERE username = ?",
                (invite_code, today_str, username),
            )
        else:
            cursor.execute(
                "INSERT INTO user_invite_codes (username, invite_code, date) VALUES (?, ?, ?)",
                (username, invite_code, today_str),
            )
        conn.commit()

    conn.close()
    return invite_code


def get_site_info():
    conn = get_db_connection()
    site_info = conn.execute("SELECT * FROM site_info LIMIT 1").fetchone()
    conn.close()
    print("Fetched site_info:", site_info)
    if site_info:
        site_info_dict = dict(site_info)
        # ensure 'content' key exists
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
        # fetch tags for this fanfic pleaase
        cursor = conn.execute(
            """
            SELECT t.name FROM tags t
            JOIN fanfic_tags ft ON t.id = ft.tag_id
            WHERE ft.fanfic_id = ?
        """,
            (fanfic_id,),
        )
        tags = [row["name"] for row in cursor.fetchall()]

        # convert fanfic row to dict and add tags
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


@app.route("/admin/generate_invite", methods=["POST"])
def generate_invite():
    if not is_admin():
        abort(403)

    # Generate the invite code
    new_code = generate_invite_code()
    created_at = datetime.now().isoformat()

    # Insert into database
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO invite_codes (code, created_at, used, redeemed_by) VALUES (?, ?, 0, NULL)",
        (new_code, created_at),
    )
    conn.commit()
    conn.close()

    # Get current user info based on session
    username = session.get("username")
    user = None
    if username:
        user = get_user(username)

    # Render the invite result template with user info
    return render_template(
        "admin/invite_result.html",
        code=new_code,
        user=user,
        username=username,
        is_logged_in=is_logged_in(),
        is_admin=is_admin(),
    )


@app.route("/admin/invite_codes")
def show_all_invite_codes():
    if not is_admin():
        abort(403)
    conn = get_db_connection()
    invite_codes = conn.execute("SELECT * FROM invite_codes").fetchall()
    conn.close()

    username = session.get("username")
    user = None
    if username:
        user = get_user(username)

    return render_template(
        "admin/invite_codes.html",
        invite_codes=invite_codes,
        is_logged_in=is_logged_in(),
        is_admin=is_admin(),
        user=user,
        username=username,
    )


@app.route("/accept_changes", methods=["POST"])
def accept_changes():
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401

    username = session["username"]
    # update user's privacy_policy_version to current through route
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET privacy_policy_version = ? WHERE username = ?",
        (CURRENT_POLICY_VERSION, username),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/")
def index():
    # fetch blog posts and fanfics
    blog_posts = get_blog_posts()
    fanfics_list = get_fanfics()

    # generate posts list
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

    # log ip
    log_ip(username=session.get("username"), page=request.path)

    # fetch current user based on session
    username = session.get("username")
    user = None
    if username:
        user = get_user(username)

    # determine if pp popup should be shown
    show_policy_popup = False
    if user and user.get("privacy_policy_version", 0) < CURRENT_POLICY_VERSION:
        show_policy_popup = True

    # format latest post timestamp
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # get filter queries
    search_query = request.args.get("search", "").lower()
    author_query = request.args.get("author", "").lower()
    filter_tag = request.args.get("tag", "").lower()
    fandom_search = request.args.get("fandom", "").lower()

    # load fanfics from DB and parse JSON fields safely
    fanfics = []
    for f in fanfics_list:
        # handle tags
        tags_data = f.get("tags", [])
        if isinstance(tags_data, str):
            if tags_data.strip():
                try:
                    f["tags"] = json.loads(tags_data)
                except json.JSONDecodeError:
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
                except json.JSONDecodeError:
                    f["fandoms"] = []
            else:
                f["fandoms"] = []
        else:
            f["fandoms"] = fandoms_data

        fanfics.append(f)

    # filtering logic
    filtered_fanfics = []

    for f in fanfics:
        tags = f.get("tags", [])
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except json.JSONDecodeError:
                tags = []

        fandoms = f.get("fandoms", [])
        if isinstance(fandoms, str):
            try:
                fandoms = json.loads(fandoms)
            except json.JSONDecodeError:
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

    # calculate top tags (refactor later on with help from trisua)
    tag_counts = {}
    for f in fanfics:
        tags = f.get("tags", [])
        # ensure tags is a list
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except json.JSONDecodeError:
                tags = [tags]
        elif not isinstance(tags, list):
            tags = [tags]

        # count each tag (must be string!!!!)
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

    # sort fanfics by number of kudos (highest to lowest)
    filtered_fanfics.sort(key=lambda f: len(f.get("kudos", [])), reverse=True)

    # pagination
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
        show_policy_popup=show_policy_popup,
    )


@app.route("/filter/tag/<path:tag>")
def filter_by_single_tag(tag):
    fanfics_list = get_fanfics()
    blog_posts = get_blog_posts()

    # fetch site info and convert to dict if needed
    site_info_row = get_site_info()
    if isinstance(site_info_row, dict):
        site_info = site_info_row
    elif hasattr(site_info_row, "_asdict"):  # for sqlite3.Row
        site_info = dict(site_info_row)
    else:
        site_info = dict(site_info_row)  # fallback

    print("Fetched site_info:", site_info)

    # convert blog posts to our yummy mummy format
    # man why the fuck did i say that
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

    # sort posts by timestamp descending
    posts.sort(key=lambda x: x["timestamp"], reverse=True)

    # latest post
    latest_post = posts[0] if posts else None

    # log ip
    log_ip(username=session.get("username"), page=request.path)
    print(
        f"Logging IP: {request.remote_addr}, User: {session.get('username')}, Page: {request.path}"
    )

    # format latest post timestamp
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # collect all tags for display
    all_tags = set()
    for f in fanfics_list:
        tags_data = f.get("tags", [])
        if isinstance(tags_data, str):
            if tags_data.strip():
                try:
                    tags_data = json.loads(tags_data)
                except json.JSONDecodeError:
                    tags_data = []
        for t in tags_data:
            # convert list to string to avoid unhashable errors
            if isinstance(t, list):
                t_str = json.dumps(t, sort_keys=True)
            elif isinstance(t, str):
                try:
                    t_parsed = json.loads(t)
                    if isinstance(t_parsed, list):
                        t_str = json.dumps(t_parsed, sort_keys=True)
                    else:
                        t_str = t
                except json.JSONDecodeError:
                    t_str = t
            else:
                t_str = str(t)
            all_tags.add(t_str)

    # initialize data dictionary
    data = {}
    data["tags"] = list(all_tags)

    # filter fanfics by the specified tag
    filtered_fanfics = [f for f in fanfics_list if tag in f.get("tags", [])]

    # get current search filters
    search_query = request.args.get("search", "")
    author_query = request.args.get("author", "")

    # count tags for top tags
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
                except json.JSONDecodeError:
                    t_parsed = t
            else:
                t_parsed = str(t)
            tag_counts[t_parsed] = tag_counts.get(t_parsed, 0) + 1

    # get top 5 tags
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tags_list = [tag for tag, count in top_tags]

    # pagination
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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        invite_code_input = request.form.get("invite_code", "").strip()

        conn = get_db_connection()  # Open connection once

        # Validate invite code if provided
        if invite_code_input:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM invite_codes WHERE code = ?", (invite_code_input,)
            )
            code_record = cursor.fetchone()

            if not code_record:
                conn.close()
                return render_template(
                    "register.html",
                    error="Invalid invite code.",
                    user=session.get("username"),
                    is_admin=is_admin(),
                    username="",
                    session=session,
                    logged_in=logged_in(),
                )

            if code_record["used"]:
                conn.close()
                return render_template(
                    "register.html",
                    error="Invite code already used.",
                    user=session.get("username"),
                    is_admin=is_admin(),
                    username="",
                    session=session,
                    logged_in=logged_in(),
                )

        # check if username exists
        existing_user = get_user(username)
        if existing_user:
            conn.close()
            abort(400)

        # hash the password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # get IP
        ip_address = request.remote_addr

        # prepare user data
        user_data = {
            "username": username,
            "password": hashed_password,
            "is_admin": False,
            "bio": "",
            "pfp": "",
            "custom_css": "",
            "display_name": "",
            "ip": ip_address,
            "privacy_policy_version": CURRENT_POLICY_VERSION,
        }

        # save user
        create_user(user_data)

        # Mark invite code as used if provided
        if invite_code_input:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE invite_codes SET used = 1, redeemed_by = ? WHERE code = ?",
                (username, invite_code_input),
            )
            conn.commit()

        conn.close()

        # log IP
        log_ip(username=session.get("username"), page=request.path)

        # log in user
        session["username"] = username

        return redirect(url_for("index"))

    # For GET request, pass parameters explicitly
    return render_template(
        "register.html",
        user=session.get("username"),
        is_admin=is_admin(),
        username="",
        session=session,
        logged_in=logged_in(),
        error=None,  # you can pass error messages if needed
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    username = ""
    user = None
    admin_status = False
    logged_in = False
    show_policy_popup = False  # flag to show popup if needed

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user(username)  # fetch user from database

        print("Fetched user:", user)  # debug print

        if not user:
            abort(404)

        # check if user is banned
        if user and user.get("banned"):
            abort(403)

        # retrieve the stored hashed password
        stored_hashed = user.get("password")  # stored as string

        # verify password with bcrypt
        if bcrypt.checkpw(password.encode("utf-8"), stored_hashed.encode("utf-8")):
            # password is correct

            # get current ip using get_client_ip() for accurate ip behind proxies
            ip_address = get_client_ip()

            # log the ip in the audit log
            log_ip(username=session.get("username"), page=request.path)

            # update the user's ip in the database
            conn = get_db_connection()
            conn.execute(
                "UPDATE users SET ip = ? WHERE username = ?", (ip_address, username)
            )
            conn.commit()
            conn.close()

            session["username"] = username
            if user:
                session["is_admin"] = user.get("is_admin", False)
            else:
                # handle the case if user is None (though, it shouldn't be here if your earlier check aborts)
                session["is_admin"] = False

            if user:
                user_policy_version = user.get("privacy_policy_version", 0)
                if user_policy_version < CURRENT_POLICY_VERSION:
                    show_policy_popup = True
            else:
                # handle the case where user is none if necessary
                pass

            print("Session 'is_admin' set to:", session["is_admin"])  # debug

            # redirect to index passing popup info if needed
            return redirect(url_for("index", show_policy_popup=show_policy_popup))
        else:
            return "Invalid credentials"

    # for get request
    logged_in = "username" in session
    if logged_in:
        username = session["username"]
        user = get_user(username)
        admin_status = session.get("is_admin", False)

        # check if user needs to accept latest privacy policy
        user_policy_version = user.get("privacy_policy_version", 0)
        print(
            "User policy version:",
            user_policy_version,
            "Show popup:",
            show_policy_popup,
        )
        if user_policy_version < CURRENT_POLICY_VERSION:
            show_policy_popup = True

    return render_template(
        "login.html",
        username=username,
        session=session,
        logged_in=logged_in,
        user=user,
        is_admin=admin_status,
        show_policy_popup=show_policy_popup,
    )


@app.route("/tos")
def tos():
    username = ""
    is_admin = False
    logged_in = False

    # check if user is logged in
    if "username" in session:
        username = session["username"]
        is_admin = session.get("is_admin", False)
        logged_in = True

    return render_template(
        "tos.html", username=username, is_admin=is_admin, logged_in=logged_in
    )


@app.route("/privacy")
def privacy():
    username = ""
    is_admin = False
    logged_in = False

    # check if user is logged in
    if "username" in session:
        username = session["username"]
        is_admin = session.get("is_admin", False)
        logged_in = True

    return render_template(
        "privacy.html", username=username, is_admin=is_admin, logged_in=logged_in
    )


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


@app.route("/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic(fic_id):
    # delete the fanfic from the database
    conn = get_db_connection()
    conn.execute("DELETE FROM fanfics WHERE id = ?", (fic_id,))
    conn.commit()
    conn.close()

    conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fic_id,))
    conn.commit()

    return redirect(url_for("profile"))


@app.route("/add_tag", methods=["POST"])
def add_tag():
    # get the tag from json request
    data_in = request.get_json()
    new_tag = data_in.get("tag", "").strip()

    if not new_tag:
        return jsonify({"success": False, "error": "No tag provided"}), 400

    # check if the tag already exists in the database
    conn = get_db_connection()
    existing = conn.execute("SELECT 1 FROM tags WHERE name = ?", (new_tag,)).fetchone()

    if existing:
        conn.close()
        return jsonify({"success": True, "message": "Tag already exists"})

    # insert the new tag
    conn.execute("INSERT INTO tags (name) VALUES (?)", (new_tag,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "tag": new_tag})


@app.route("/profile/<username>")
def user_profile(username):
    # fetch user details from the database
    user = get_user(username)

    # check if user exists
    if not user:
        abort(404)

    # ensure the user is a dictionary or similar mutable object
    if isinstance(user, dict):
        user["username"] = username
    else:
        # handle unexpected data structure
        abort(500)  # spit out to custom error page

    # check if the current logged-in user is the owner
    is_owner = username == session.get("username")
    logged_in = "username" in session
    admin_status = is_admin()

    # fetch fanfics owned by the user from the database
    conn = get_db_connection()
    fanfics_rows = conn.execute(
        "SELECT * FROM fanfics WHERE owner = ?", (username,)
    ).fetchall()
    conn.close()

    # convert to list of dicts
    fanfics = [dict(row) for row in fanfics_rows]

    # pagination
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

    # log ip
    log_ip(username=username, page=request.path)

    # fetch fanfics owned by the user from the database
    conn = get_db_connection()
    fanfics_rows = conn.execute(
        "SELECT * FROM fanfics WHERE owner = ?", (username,)
    ).fetchall()
    conn.close()

    fanfics = [dict(row) for row in fanfics_rows]

    # pagination
    page = int(request.args.get("page", 1))
    per_page = 3
    total_fanfics = len(fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = fanfics[start:end]

    notes_data = {}  # remove laterrrr

    return render_template(
        "profile.html",
        fanfics=display_fanfics,
        notes=notes_data,
        username=username,
        session=session,
        logged_in=True,
        user=user,
        is_owner=True,  # since this would be the persons profile
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


@app.route("/submit", methods=["GET", "POST"])
def submit():
    if not logged_in():
        return redirect(url_for("login"))

    log_ip(username=session.get("username"), page=request.path)

    conn = get_db_connection()

    # fetch all tags for display
    all_tags_rows = conn.execute("SELECT name FROM tags").fetchall()
    all_tags = [row["name"] for row in all_tags_rows]

    if request.method == "POST":
        # generate new fanfic id
        max_id_row = conn.execute("SELECT MAX(id) FROM fanfics").fetchone()
        new_id = (max_id_row[0] or 0) + 1

        # get form data
        # note: 'tags' is a JSON string sent from the form
        tags_json = request.form.get("tags", "[]")
        try:
            combined_tags = json.loads(tags_json)
            # ensure it's a list
            if not isinstance(combined_tags, list):
                combined_tags = []
        except json.JSONDecodeError:
            combined_tags = []

        # add new_tag if provided
        new_tag = request.form.get("new_tag", "").strip()
        if new_tag:
            if new_tag not in combined_tags:
                combined_tags.append(new_tag)

        age_rating = request.form.get("age_rating")
        content_text = request.form.get("content")

        # insert new fanfic record
        conn.execute(
            """
            INSERT INTO fanfics (
                id, title, author, owner, fandom, comments, kudos, age_rating, content
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                content_text,
            ),
        )

        # handle tags: insert new tags and create associations
        for tag in combined_tags:
            print(f"Inserting or ignoring tag: {tag}")
            conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            # fetch the tag id
            tag_row = conn.execute(
                "SELECT id FROM tags WHERE name = ?", (tag,)
            ).fetchone()
            if tag_row:
                print(f"Associating tag '{tag}' with fanfic {new_id}")
                conn.execute(
                    "INSERT OR IGNORE INTO fanfic_tags (fanfic_id, tag_id) VALUES (?, ?)",
                    (new_id, tag_row["id"]),
                )

        # commit all changes
        conn.commit()
        conn.close()

        print("New fanfic added with content.")
        return redirect(url_for("view_fic", fid=new_id))

    # for GET request, just render the form
    return render_template(
        "fanfic/submit.html",
        logged_in=True,
        tags=[],
        is_admin=is_admin(),
    )


@app.route("/fic/<int:fid>")
def view_fic(fid):
    conn = get_db_connection()

    # fetch the main fanfic record
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # parse comments
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # deduplicate comments
    unique_comments = []
    seen = set()
    for c in comments:
        key = (c["name"], c["content"])
        if key not in seen:
            seen.add(key)
            unique_comments.append(c)
    fanfic["comments"] = unique_comments

    # parse kudos
    kudos_json = fanfic.get("kudos")
    if kudos_json:
        try:
            kudos_list = json.loads(kudos_json)
        except json.JSONDecodeError:
            kudos_list = []
    else:
        kudos_list = []

    # deduplicate kudos
    kudos = list(set(kudos_list))

    # fetch chapters (but dont display them or else it breaks)
    chapters_rows = conn.execute(
        "SELECT * FROM chapters WHERE fanfic_id = ?", (fid,)
    ).fetchall()

    # fetch tags
    tags_rows = conn.execute(
        "SELECT t.name FROM tags t JOIN fanfic_tags ft ON t.id = ft.tag_id WHERE ft.fanfic_id = ?",
        (fid,),
    ).fetchall()

    conn.close()

    # process chapters content (not used for display)
    chapters = [dict(c) for c in chapters_rows] if chapters_rows else []
    for chapter in chapters:
        if "content" in chapter:
            chapter["content"] = re.sub(
                r"^\s+", "", chapter["content"], flags=re.MULTILINE
            ).strip()
            chapter["content"] = re.sub(r"\n\s*\n+", "\n\n", chapter["content"])

    # extract tag names
    tags = [row["name"] for row in tags_rows]
    fanfic["tags"] = tags

    # check user session and get admin status
    user = get_user(session.get("username", ""))
    is_admin = user.get("is_admin", False) if user else False
    return render_template(
        "fanfic/view_fic.html",
        fic_content=fanfic["content"],
        comments=comments,
        kudos=kudos,
        fic=fanfic,
        logged_in=("username" in session),
        is_admin=is_admin,
    )


@app.route("/edit/<int:fid>", methods=["GET", "POST"])
def edit_fic(fid):
    # fetch the fanfic from the database
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        return "Fanfic not found"

    # check ownership and login
    if not logged_in() or fanfic_row["owner"] != session["username"]:
        conn.close()
        return "Unauthorized"

    # fetch all tags for display
    all_tags_rows = conn.execute("SELECT name FROM tags").fetchall()
    all_tags = [row["name"] for row in all_tags_rows]

    # fetch chapters
    chapters_rows = conn.execute(
        "SELECT * FROM chapters WHERE fanfic_id = ? ORDER BY id", (fid,)
    ).fetchall()
    chapters = [dict(c) for c in chapters_rows]

    # fetch tags associated with this fanfic
    tags_rows = conn.execute(
        "SELECT t.name FROM tags t JOIN fanfic_tags ft ON t.id = ft.tag_id WHERE ft.fanfic_id = ?",
        (fid,),
    ).fetchall()
    current_tags = [row["name"] for row in tags_rows]

    # parse comments JSON
    comments_json = fanfic_row["comments"]
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # parse kudos JSON
    kudos_json = fanfic_row["kudos"]
    if kudos_json:
        try:
            kudos = json.loads(kudos_json)
        except json.JSONDecodeError:
            kudos = []
    else:
        kudos = []

    # handle POST request for updating fanfic
    if request.method == "POST":
        # Parse tags from form
        tags_str = request.form.get("tags", "")
        selected_tags = [tag.strip() for tag in tags_str.split(",") if tag.strip()]

        # handle new tag input
        new_tag = request.form.get("new_tag", "").strip()
        if new_tag:
            selected_tags.append(new_tag)

        # deduplicate tags
        updated_tags = list(set(selected_tags))

        # collect chapters
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

        # update main fanfic fields including content
        conn.execute(
            "UPDATE fanfics SET title=?, fandom=?, age_rating=?, content=? WHERE id=?",
            (
                request.form["title"],
                request.form["fandom"],
                request.form.get("age_rating", "13+"),
                request.form.get("content", ""),  # <-- your story content
                fid,
            ),
        )

        # update chapters: delete existing and insert new
        conn.execute("DELETE FROM chapters WHERE fanfic_id = ?", (fid,))
        for chapter in chapters:
            conn.execute(
                "INSERT INTO chapters (fanfic_id, title, content) VALUES (?, ?, ?)",
                (fid, chapter["title"], chapter["content"]),
            )

        # update tags: clear old associations
        conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fid,))

        # insert tags and create associations
        for tag in updated_tags:
            conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            tag_id_row = conn.execute(
                "SELECT id FROM tags WHERE name = ?", (tag,)
            ).fetchone()
            if tag_id_row:
                conn.execute(
                    "INSERT INTO fanfic_tags (fanfic_id, tag_id) VALUES (?, ?)",
                    (fid, tag_id_row["id"]),
                )

        conn.commit()
        conn.close()
        return redirect(url_for("view_fic", fid=fid))

    conn.close()

    # render edit form with current data
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
            "content": fanfic_row["content"],  # safe to access directly
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

    # connect to the database
    conn = get_db_connection()

    # fetch the fanfic record
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # parse current kudos
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

        # save updated kudos back to the database
        updated_kudos_json = json.dumps(kudos_list)
        conn.execute(
            "UPDATE fanfics SET kudos = ? WHERE id = ?", (updated_kudos_json, fid)
        )
        conn.commit()

        # log ip
        log_ip(username=user, page=request.path)

    conn.close()

    return redirect(url_for("view_fic", fid=fid))


def user_exists(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user is not None


def user_exists_in_comments(fanfic_id, username):
    conn = get_db_connection()
    fanfic_row = conn.execute(
        "SELECT comments FROM fanfics WHERE id = ?", (fanfic_id,)
    ).fetchone()
    conn.close()
    if not fanfic_row or not fanfic_row["comments"]:
        return False
    try:
        comments = json.loads(fanfic_row["comments"])
    except json.JSONDecodeError:
        return False
    for comment in comments:
        if comment.get("name") == username:
            return True
    return False


def linkify_mentions(content, fanfic_id, replied_username=None):
    def replace_mention(match):
        username = match.group(1)
        # if the mention is the replied user, link to their profile
        if username == replied_username:
            return f'<a href="{url_for("profile", username=username)}">@{username}</a>'
        # otherwise, check if the user exists in comments
        elif user_exists_in_comments(fanfic_id, username):
            return f'<a href="{url_for("profile", username=username)}">@{username}</a>'
        else:
            return f"@{username}"

    pattern = r"@(\w+)"
    return re.sub(pattern, replace_mention, content)


@app.route("/comment/<int:fid>", methods=["POST"])
def add_comment(fid):
    if not logged_in():
        return redirect(url_for("login"))

    # fetch current fanfic record
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        abort(404)

    fanfic = dict(fanfic_row)

    # parse existing comments JSON
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # prepare new comment
    content = request.form["content"]
    content_with_links = linkify_mentions(content, fid)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = session["username"]
    user = get_user(username)
    pfp_path = user["pfp"] if user and "pfp" in user else ""

    new_comment = {
        "name": username,
        "content": content_with_links,
        "timestamp": timestamp,
        "pfp": pfp_path,
        "user": user,
    }

    # append new comment
    comments.append(new_comment)

    # save updated comments JSON back to the database
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

    # fetch the fanfic from database
    conn = get_db_connection()
    fanfic_row = conn.execute("SELECT * FROM fanfics WHERE id = ?", (fid,)).fetchone()
    if not fanfic_row:
        conn.close()
        return "Fanfic not found"

    fanfic = dict(fanfic_row)

    # decode comments JSON
    comments_json = fanfic.get("comments")
    if comments_json:
        try:
            comments = json.loads(comments_json)
        except json.JSONDecodeError:
            comments = []
    else:
        comments = []

    # validate index
    if comment_index < 0 or comment_index >= len(comments):
        conn.close()
        abort(404)

    comment = comments[comment_index]
    current_user = session.get("username")
    is_admin = session.get("is_admin", False)

    # check permissions: admins can delete any, users only their own
    if is_admin:
        # if admins are allowed to delete any comment
        pass
    else:
        # then regular users can only delete their own comments
        if comment["name"] != current_user:
            conn.close()
            abort(403)

    # remove comment
    comments.pop(comment_index)

    # save updated comments json back to database
    updated_comments_json = json.dumps(comments)
    conn.execute(
        "UPDATE fanfics SET comments = ? WHERE id = ?", (updated_comments_json, fid)
    )
    conn.commit()
    conn.close()

    # log deletion
    log_ip(username=current_user, page=request.path)

    return redirect(url_for("view_fic", fid=fid))


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    current_ip = request.remote_addr

    # check if IP is banned
    if is_ip_banned(current_ip):
        abort(403)

    # check user session and admin status
    username = session.get("username")
    if not username:
        abort(404)

    user = get_user(username)
    if not user or not user.get("is_admin"):
        abort(403)

    # log access
    log_ip(username=username, page=request.path)

    # handle banning IP via POST
    if request.method == "POST":
        ip_to_ban = request.form.get("ip")
        if ip_to_ban:
            save_banned_ip(ip_to_ban)
            return f"IP {ip_to_ban} has been banned.", 200

    # fetch all users
    users = get_all_users()

    # fetch latest ip from ip_logs for each user:
    # SQL: get the most recent log per user
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT il.ip, il.username
        FROM ip_logs il
        JOIN (
            SELECT username, MAX(timestamp) as max_time
            FROM ip_logs
            GROUP BY username
        ) latest_log ON il.username = latest_log.username AND il.timestamp = latest_log.max_time
    """)
    latest_logs = {row["username"]: row["ip"] for row in cursor.fetchall()}

    # close connection
    conn.close()

    # prepare user_ips dict for template
    user_ips = {u["username"]: latest_logs.get(u["username"], "Unknown") for u in users}

    # fetch fanfics, if applicable
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
        user_logs=None,
    )


# add it so it deletes fics, notes, comments etc


@app.route("/admin/delete_user/<username>", methods=["POST"])
def delete_user(username):
    if not is_admin():
        abort(403)

    # fetch user from database
    user = get_user(username)
    if not user:
        abort(404)

    # delete user from database
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    except Exception as e:
        # log error if needed
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
        # check if fanfic exists
        fanfic = conn.execute(
            "SELECT * FROM fanfics WHERE id = ?", (fic_id,)
        ).fetchone()
        if not fanfic:
            abort(404)

        # delete fanfic
        conn.execute("DELETE FROM fanfics WHERE id = ?", (fic_id,))
        # also delete associated chapters, tags, etc., if applicable
        conn.execute("DELETE FROM chapters WHERE fanfic_id = ?", (fic_id,))
        conn.execute("DELETE FROM fanfic_tags WHERE fanfic_id = ?", (fic_id,))
        # commit changes
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

        # only allow admins to set display names
        if user and user.get("is_admin"):
            # update display_name in the database directly
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

    # for get request, ensure display_name exists in the database
    if user is None:
        # handle the case where user is none. just skip
        pass
    else:
        if not user.get("display_name"):
            # set display_name to username if not set
            conn = get_db_connection()
            conn.execute(
                "UPDATE users SET display_name = ? WHERE username = ?",
                (user["username"], username),
            )
            conn.commit()
            conn.close()

        # re-fetch user if needed
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

    # connect to db
    conn = get_db_connection()
    cursor = conn.cursor()

    # count total notes for pagination
    total_notes = cursor.execute(
        "SELECT COUNT(*) FROM notes WHERE owner = ?", (username,)
    ).fetchone()[0]

    # pagination setup
    page = int(request.args.get("page", 1))
    per_page = 10
    total_pages = (total_notes + per_page - 1) // per_page
    start = (page - 1) * per_page

    # fetch notes for the current page
    cursor.execute(
        "SELECT id, content FROM notes WHERE owner = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (username, per_page, start),
    )

    notes_rows = cursor.fetchall()
    conn.close()

    # format notes
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

    # connect to db
    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch the note by id
    cursor.execute("SELECT owner, content FROM notes WHERE id = ?", (note_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    owner = row["owner"]
    content = row["content"]

    # authorization check: only owner can view
    if owner != username:
        abort(403)

    # if content is JSON, decode it
    try:
        note_data = json.loads(content)
        # if note_data is a dict with 'content', extract it
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

        # insert into database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (owner, content) VALUES (?, ?)",
            (username, sanitized_content),
        )
        conn.commit()

        # get the new note's id
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
    # fetch the note from the database
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

    # check ownership
    if owner != current_user:
        conn.close()
        print(f"User {current_user} unauthorized to edit note {note_id}")
        abort(403)

    log_ip(username=current_user, page=request.path)

    if request.method == "POST":
        if request.form.get("delete"):
            # delete the note
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
    # connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch all blog posts with authors
    cursor.execute("""
        SELECT bp.id, bp.title, bp.content, bp.timestamp, u.display_name, bp.author
        FROM blog_posts bp
        LEFT JOIN users u ON bp.author = u.username
    """)
    posts_rows = cursor.fetchall()
    conn.close()

    # prepare posts list
    posts = []
    for row in posts_rows:
        # safely get 'display_name'
        display_name = (
            row["display_name"]
            if "display_name" in row and row["display_name"]
            else None
        )
        # safely get 'author'
        author_value = row["author"] if "author" in row else ""

        # fallback for author display
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

    # sort posts by timestamp descending
    posts.sort(key=lambda x: x["timestamp"], reverse=True)
    print(f"Number of posts in list: {len(posts)}")

    # pagination
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
    # connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch the post along with author display name
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

    # safely get display_name; fallback to 'author' if missing
    display_name = (
        row["display_name"]
        if "display_name" in row.keys() and row["display_name"]
        else None
    )
    author_value = row["author"] if "author" in row.keys() else ""

    author_display = display_name if display_name else author_value

    # prepare post data
    post = {
        "id": row["id"],
        "title": row["title"],
        "content": row["content"],
        "timestamp": row["timestamp"],
        "author": author_display,
    }

    # format timestamp
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

    # check if user is admin
    if not user or not user.get("is_admin", False):
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        display_name = user.get("display_name", username) if user else username

        # insert new post into database
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
    # fetch the post from the database
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

    # check if user is admin
    username = session.get("username")
    user = get_user(username) if username else None

    if not user or not user.get("is_admin", False):
        conn.close()
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        timestamp = datetime.now().isoformat()

        # update the post in the database
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
        # render the edit form with the current post data
        conn.close()
        return render_template(
            "admin/edit_blog_post.html",
            post=row,
            post_id=post_id,
            is_admin=is_admin(),
            logged_in=logged_in(),
        )


@app.route("/blog/<post_id>/delete", methods=["POST"])
def delete_blog_post(post_id):
    # connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # check if the post exists
    cursor.execute("SELECT id FROM blog_posts WHERE id = ?", (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        abort(404)

    # check admin permissions
    username = session.get("username")
    user = get_user(username) if username else None
    if not user or not user.get("is_admin", False):
        conn.close()
        abort(403)

    # delete the post
    cursor.execute("DELETE FROM blog_posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("blog"))


@app.route("/about")
def about():
    # fetch site info from database or set defaults
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT title, content FROM site_info")
    site_info = cursor.fetchone()
    conn.close()

    # prepare data for template
    if site_info:
        current_info = {"title": site_info["title"], "content": site_info["content"]}
    else:
        current_info = {"title": "Default Title", "content": "Default Content"}

    return render_template(
        "about.html",
        site_info=current_info,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/site-info", methods=["GET", "POST"])
def edit_site_info():
    # connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        # get updated info from form
        title = request.form.get("title")
        content = request.form.get("content")

        # check if site info exists
        cursor.execute("SELECT * FROM site_info")
        existing = cursor.fetchone()

        if existing:
            # update existing record
            cursor.execute(
                "UPDATE site_info SET title = ?, content = ?", (title, content)
            )
        else:
            # insert new record if not exists
            cursor.execute(
                "INSERT INTO site_info (title, content) VALUES (?, ?)", (title, content)
            )

        conn.commit()
        conn.close()
        return redirect(url_for("about"))

    # for GET, fetch current site info
    cursor.execute("SELECT title, content FROM site_info")
    site_info = cursor.fetchone()
    conn.close()

    # prepare data for template
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
    # connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch all users
    cursor.execute("SELECT username FROM users")
    users_list = [row["username"] for row in cursor.fetchall()]

    # fetch ip logs
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
    per_page = 20
    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch total count
    cursor.execute("SELECT COUNT(*) FROM ip_logs")
    total_count = cursor.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page

    # fetch logs for current page
    cursor.execute(
        "SELECT username, ip, timestamp, page FROM ip_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    )
    logs_rows = cursor.fetchall()

    # convert to list of dicts
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

    # determine if there are next or previous pages
    has_prev = page > 1
    has_next = page < total_pages

    return render_template(
        "admin/all_logs.html",
        logs=all_logs,
        current_page=page,
        total_pages=total_pages,
        has_prev=has_prev,
        has_next=has_next,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/logs/<username>")
def user_logs(username):
    conn = get_db_connection()
    cursor = conn.cursor()

    # fetch all users
    cursor.execute("SELECT username FROM users")
    users = [row["username"] for row in cursor.fetchall()]

    # fetch ip logs for the specific user
    cursor.execute(
        "SELECT ip, timestamp, page FROM ip_logs WHERE username = ? ORDER BY timestamp DESC",
        (username,),
    )
    logs = cursor.fetchall()

    # convert logs to list of dicts for easier use in template
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
