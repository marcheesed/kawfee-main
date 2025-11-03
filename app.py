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
import os
import re
from jinja2 import pass_environment
import bleach
from datetime import datetime, timedelta

from typing import Any
import ast


note: Any = None

app = Flask(__name__)
app.secret_key = "your_secret_key"

DATA_FILE = "data.json"

data = {}


@app.context_processor
def inject_site_info():
    global data
    if data is None:
        load_data()
    return dict(site_info=data.get("site_info", {}))


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


def load_data():
    global data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
    else:
        data = {
            "ip_logs": [],
            "banned_ips": [],
            "users": {},
            "fanfics": [],
            "blog_posts": [],
            "notes": {},
            "tags": [],
            "site_info": {},
        }


def save_data():
    global data
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


load_data()
banned_ips = set()


def log_ip(username=None, page=None):
    global data
    if "ip_logs" not in data:
        data["ip_logs"] = []

    if "user_logs" not in data:
        data["user_logs"] = {}

    ip = request.remote_addr
    now = datetime.now()

    if username:
        if not isinstance(username, str):
            # ensure username is a string
            username = str(username)
            # i forgot what this does fuck fuck fuck
        if username not in data["user_logs"]:
            data["user_logs"][username] = []

        user_logs = data["user_logs"][username]

        # DONT DO THIS
        existing_log = None
        print("user_logs:", user_logs)
        print("user_logs type:", type(user_logs))
        for log in user_logs:
            print("log:", log)
            if log["ip"] == ip and datetime.fromisoformat(
                log["timestamp"]
            ) > now - timedelta(minutes=10):
                existing_log = log
                break

        if existing_log:
            existing_log["timestamp"] = now.isoformat()
        else:
            user_logs.append({"ip": ip, "timestamp": now.isoformat(), "page": page})

    save_data()


def load_banned_ips():
    # load the ip data at startup
    load_data()


def save_banned_ip(ip):
    if ip not in data["banned_ips"]:
        data["banned_ips"].append(ip)
        save_data()


def load_users():
    global data
    return data


def save_users(updated_data):
    global data
    data = updated_data

    # what is this dude WHY DOES IT BREAK IF I DELETE IT
    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

    save_data(data)


# save data
def save_data():
    global data
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


# helper to check login status :)
def logged_in():
    return "username" in session


def get_user(username):
    with open("data.json", "r") as f:
        data = json.load(f)
    return data["users"].get(username)


def save_user(user):
    with open("data.json", "r+") as f:
        data = json.load(f)
        username = user["username"]
        # update user info
        data["users"][username] = user
        # rewrite the entire file because i hate my life
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()


# check if admin
def is_admin():
    if not logged_in():
        return False
    username = session["username"]
    user_info = data["users"].get(username)
    print("User info:", user_info)  # debug print
    if isinstance(user_info, dict):  # check if it's a dict
        return user_info.get("is_admin", False)
    return False


def save_user(user):
    data = load_users()
    old_username = user.get("old_username", user["username"])  # handle username change
    data["users"][old_username] = user  # update user info

    # if username has changed, remove the old key!
    if old_username != user["username"]:
        del data["users"][old_username]

    save_users(data)


@app.before_request
def check_ban():
    load_banned_ips()  # load the list each request or once during startup
    ip = request.remote_addr
    if ip in banned_ips:
        # generic ip banned message
        return (
            "Your IP has been banned. Please contact our support team to refute any unfair claims, and be sure to reread our terms of service before doing so.",
            403,
        )


# i hate this i hat ethis
@app.route("/")
def index():
    # use the global data
    global data

    # load blog posts
    blog_posts = data.get("blog_posts", {})
    posts = [
        {
            "id": post_id,
            "title": post["title"],
            "content": post["content"],
            "author": post["author"],
            "timestamp": post["timestamp"],
        }
        for post_id, post in blog_posts.items()
    ]
    # AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA sort function
    posts.sort(key=lambda x: x["timestamp"], reverse=True)

    # get latest post
    latest_post = posts[0] if posts else None

    log_ip(username=session.get("username"), page=request.path)
    print(
        f"Logging IP: {request.remote_addr}, User: {session.get('username')}, Page: {request.path}"
    )

    # add date to post
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # filtering fanfics
    search_query = request.args.get("search", "").lower()
    author_query = request.args.get("author", "").lower()
    filter_tag = request.args.get("tag", "")

    # new fandom filter parameter
    fandom_search = request.args.get("fandom", "").lower()

    fanfics_list = data.get("fanfics", [])

    # count tags
    tag_counts = {}
    for f in fanfics_list:
        for tag in f.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    # top 5 tags
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tags_list = [tag for tag, count in top_tags]

    # all tags
    all_tags = list(tag_counts.keys())

    # filter fanfics based on search across title author tags fandoms
    filtered_fanfics = fanfics_list
    if search_query:
        filtered_fanfics = [
            f
            for f in filtered_fanfics
            if (
                search_query in f["title"].lower()
                or search_query in f["author"].lower()
                or any(search_query in tag.lower() for tag in f.get("tags", []))
                or any(
                    search_query in fandom.lower() for fandom in f.get("fandoms", [])
                )
            )
        ]
    if author_query:
        filtered_fanfics = [
            f for f in filtered_fanfics if author_query in f["author"].lower()
        ]
    if filter_tag:
        filtered_fanfics = [f for f in filtered_fanfics if filter_tag in f["tags"]]

    # additional filter for fandom search
    if fandom_search:
        filtered_fanfics = [
            f
            for f in filtered_fanfics
            if ("fandom" in f and fandom_search in f["fandom"].lower())
        ]

    # paaaaaages im amy rose i like to play
    page = int(request.args.get("page", 1))
    per_page = 6
    total_fanfics = len(filtered_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = filtered_fanfics[start:end]
    # why are you YELLOW
    return render_template(
        "index.html",
        fanfics=display_fanfics,
        all_tags=sorted(all_tags),
        top_tags=top_tags_list,
        current_tag=filter_tag,
        search_query=request.args.get("search", ""),
        author_query=request.args.get("author", ""),
        logged_in=logged_in(),
        tags=all_tags,
        is_admin=is_admin(),
        show_back_link=False,
        latest_post=latest_post,
        current_page=page,
        total_pages=total_pages,
        # pass the current filter values to the template for form pre-filling
        current_filters={
            "search": request.args.get("search", ""),
            "author": request.args.get("author", ""),
            "tag": filter_tag,
            "age_rating": request.args.get("age_rating", ""),
            "fandom": request.args.get("fandom", ""),  # new
        },
    )


@app.route("/filter/tag/<path:tag>")
def filter_by_single_tag(tag):
    global data
    # STOP RELOADING YOU FUCKER
    fanfics_list = data.get("fanfics", [])

    # laod
    blog_posts = data.get("blog_posts", {})
    posts = [
        {
            "id": post_id,
            "title": post["title"],
            "content": post["content"],
            "author": post["author"],
            "timestamp": post["timestamp"],
        }
        for post_id, post in blog_posts.items()
    ]
    # both completely naked and covered in oil
    posts.sort(key=lambda x: x["timestamp"], reverse=True)

    # latest post
    latest_post = posts[0] if posts else None

    log_ip(username=session.get("username"), page=request.path)
    print(
        f"Logging IP: {request.remote_addr}, User: {session.get('username')}, Page: {request.path}"
    )

    # formatted date to latest_post
    if latest_post:
        latest_post["formatted_timestamp"] = datetime.fromisoformat(
            latest_post["timestamp"]
        ).strftime("%B %d, %Y at %I:%M %p")

    # get all tags for display
    all_tags = set()
    for f in fanfics_list:
        all_tags.update(f.get("tags", []))
    data["tags"] = list(all_tags)

    # filter fanfics by the specified tag
    filtered_fanfics = [f for f in fanfics_list if tag in f["tags"]]

    # get current filter / search parameters if needed
    search_query = request.args.get("search", "")
    author_query = request.args.get("author", "")

    # counttags
    tag_counts = {}
    for f in fanfics_list:
        for tag in f.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    # top 5 tagssss
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tags_list = [tag for tag, count in top_tags]

    # i want a beer! i want a beer! i want a beer!
    page = int(request.args.get("page", 1))
    per_page = 6
    total_fanfics = len(filtered_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = filtered_fanfics[start:end]

    return render_template(
        "index.html",
        fanfics=filtered_fanfics,
        all_tags=sorted(all_tags),
        top_tags=top_tags_list,
        current_tag=tag,
        search_query=search_query,
        author_query=author_query,
        logged_in=logged_in(),
        current_page=page,
        tags=data["tags"],
        is_admin=is_admin(),
        show_back_link=True,
        latest_post=latest_post,
        total_pages=total_pages,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    global data
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in data["users"]:
            return "Username already exists!"

        # log the ip and prevent duplicates if needed
        log_ip(username=session.get("username"), page=request.path)

        # get the current ip address
        ip_address = request.remote_addr

        # add user with ip info
        data["users"][username] = {
            "password": password,
            "is_admin": False,
            "bio": "",
            "ip": ip_address,
        }

        # save to disk
        save_data()

        session["username"] = username
        return redirect(url_for("index"))

    # for get request render the registration form
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
    global data  # declare to access and modify the global data

    username = ""
    user = None
    admin_status = False
    logged_in = False

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user(username)
        print("Fetched user:", user)  # debug print

        if not user:
            return "User not found", 404

        # check if user is banned
        if user.get("banned"):
            return "This user has been banned.", 403

        if data["users"][username]["password"] == password:
            # get current ip
            ip_address = request.remote_addr
            # log the ip in the audit log
            log_ip(username=session.get("username"), page=request.path)

            # update the user's stored ip
            data["users"][username]["ip"] = ip_address

            # set session variables
            session["username"] = username
            session["is_admin"] = user.get("is_admin", False)

            print("Session 'is_admin' set to:", session["is_admin"])  # debug

            return redirect(url_for("index"))
        else:
            return "Invalid credentials"

    # for get request prepare variables for rendering the template
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
    global data
    # remove the fic with matching id
    data["fanfics"] = [fic for fic in data["fanfics"] if fic["id"] != fic_id]

    save_data()

    return redirect(url_for("profile"))


@app.route("/add_tag", methods=["POST"])
def add_tag():
    global data  # access the global data

    # get the tag from json request
    data_in = request.get_json()
    new_tag = data_in.get("tag", "").strip()

    if not new_tag:
        return jsonify({"success": False, "error": "No tag provided"}), 400

    # initialize tags list if not present
    if "tags" not in data:
        data["tags"] = []

    # check if the tag already exists
    if new_tag in data["tags"]:
        return jsonify({"success": True, "message": "Tag already exists"})

    # add new tag
    data["tags"].append(new_tag)

    # save changes
    save_data()

    return jsonify({"success": True, "tag": new_tag})


@app.route("/profile/<username>")
def user_profile(username):
    global data  # declare to access the global data
    user = get_user(username)
    print("Fetched user:", user)  # Debug
    if not user:
        return "User not found", 404
    user["username"] = username
    admin_status = is_admin()
    user_fanfics = [fic for fic in data["fanfics"] if fic["owner"] == username]
    is_owner = username == session.get("username")
    print("Session username:", session.get("username"))
    print("Is owner:", is_owner)
    logged_in = "username" in session
    # beer
    page = int(request.args.get("page", 1))
    per_page = 3
    total_fanfics = len(user_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page

    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = user_fanfics[start:end]
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
    is_logged_in = logged_in()
    if not is_logged_in:
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user(username)
    if not user:
        return "User not found", 404

    # data
    global data

    # extract botes
    notes_data = data.get("notes", {})

    log_ip(username=session.get("username"), page=request.path)

    # add username
    user["username"] = username
    admin_status = is_admin()

    # filter fics
    user_fanfics = [fic for fic in data["fanfics"] if fic["owner"] == username]

    # assume the logged in user is viewing their own profile
    is_owner = True

    # beer berr beeeeee vodka truqila
    page = int(request.args.get("page", 1))
    per_page = 3
    total_fanfics = len(user_fanfics)
    total_pages = (total_fanfics + per_page - 1) // per_page

    start = (page - 1) * per_page
    end = start + per_page
    display_fanfics = user_fanfics[start:end]

    return render_template(
        "profile.html",
        fanfics=display_fanfics,
        notes=notes_data,
        username=username,
        session=session,
        logged_in=is_logged_in,
        user=user,
        is_owner=is_owner,
        is_admin=admin_status,
        current_page=page,
        total_pages=total_pages,
    )


@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    global data

    print("edit_profile route hit")
    logged_in = "username" in session
    if not logged_in:
        return redirect(url_for("login"))

    old_username = session["username"]
    user = get_user(old_username)
    if not user:
        return "User not found", 404

    if request.method == "POST":
        # get form data
        new_username = request.form.get("username").strip()
        new_bio_raw = request.form.get("bio", "")
        pfp_file = request.files.get("pfp")
        new_custom_css = request.form.get("custom_css")

        # bleach
        new_bio = sanitize_bio(new_bio_raw.strip())

        log_ip(username=session.get("username"), page=request.path)

        # pfps
        if pfp_file and pfp_file.filename != "":
            filename = secure_filename(pfp_file.filename)
            upload_dir = os.path.join(app.static_folder, "pfps")
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)
            print("Saving file to:", upload_path)  # Debug
            pfp_file.save(upload_path)
            user["pfp"] = f"pfps/{filename}"
            print("Stored image path:", user["pfp"])  # Debug

        # username change
        if new_username != old_username:
            # move user data to new key
            data["users"][new_username] = data["users"].pop(old_username)
            # update session username
            session["username"] = new_username

            # update all fanfics owned and authored by that user
            for fic in data["fanfics"]:
                if fic["owner"] == old_username:
                    fic["owner"] = new_username
                if fic["author"] == old_username:
                    fic["author"] = new_username

            # update all notes owned by the user
            for note_id, note_value in data.get("notes", {}).items():
                # handle whatever this is being delete dproably
                if isinstance(note_value, str):
                    try:
                        note_obj = json.loads(note_value)
                    except json.JSONDecodeError:
                        continue
                elif isinstance(note_value, dict):
                    note_obj = note_value
                else:
                    continue

                if note_obj.get("owner") == old_username:
                    note_obj["owner"] = new_username
                    # save back the note
                    if isinstance(note_value, str):
                        data["notes"][note_id] = json.dumps(note_obj)
                    else:
                        data["notes"][note_id] = note_obj

            # update comment usernames from old to ne
            for fic in data["fanfics"]:
                for comment in fic.get("comments", []):
                    if comment.get("name") == old_username:
                        comment["name"] = new_username

        # update user data
        user = get_user(new_username)  # get the updated user object after moving
        user["username"] = new_username
        user["bio"] = new_bio
        user["custom_css"] = new_custom_css

        save_user(user)
        save_data()

        return redirect(url_for("profile"))

    return render_template(
        "edit_profile.html",
        user=user,
        is_admin=is_admin(),
        username=old_username,
        session=session,
        is_owner=True,
        logged_in=logged_in,
    )


@app.route("/submit", methods=["GET", "POST"])
def submit():
    global data
    if not logged_in():
        return redirect(url_for("login"))

    # update global tags list from all fanfics
    all_tags = set()
    for f in data["fanfics"]:
        all_tags.update(f.get("tags", []))
    data["tags"] = list(all_tags)
    save_data()

    log_ip(username=session.get("username"), page=request.path)
    tags = data["tags"]

    if request.method == "POST":
        # gen fanfic id
        new_id = max([f["id"] for f in data["fanfics"]], default=0) + 1

        # collect all chapters
        chapters = []
        pattern_title = re.compile(r"chapter_title_(\d+)")
        pattern_content = re.compile(r"chapter_content_(\d+)")
        for key in request.form:
            match = pattern_title.match(key)
            if match:
                index = match.group(1)
                title = request.form.get(f"chapter_title_{index}")
                content = request.form.get(f"chapter_content_{index}")
                if title or content:  # ignore empty
                    # the new norm
                    content = re.sub(r"\n+", "\n", content.strip()) if content else ""
                    chapters.append({"title": title, "content": content})

        print("Collected chapters:", chapters)

        # get tags selected
        selected_tags = request.form.getlist("tags")
        # get new tag entered
        new_tag = request.form.get("new_tag", "").strip()

        # combine tags avoiding dupes
        combined_tags = list(set(selected_tags))
        if new_tag:
            combined_tags.append(new_tag)

        age_rating = request.form.get("age_rating")

        new_fic = {
            "id": new_id,
            "title": request.form["title"],
            "author": session["username"],
            "owner": session["username"],
            "fandom": request.form["fandom"],
            "stats": {"words": 0, "chapters": len(chapters), "kudos": 0},
            "tags": combined_tags,
            "age_rating": age_rating,
            "chapters": chapters,
            "comments": [],
            "kudos": [],
        }

        data["fanfics"].append(new_fic)
        print("New fanfic added with chapters:", new_fic["chapters"])
        save_data()

        return redirect(url_for("view_fic", fid=new_fic["id"]))

    return render_template(
        "fanfic/submit.html",
        data=data,
        logged_in=logged_in(),
        tags=tags,
        is_admin=is_admin(),
    )


@app.route("/fic/<int:fid>")
def view_fic(fid):
    global data

    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found", 404

    # normalize each chapter's content
    for chapter in fic.get("chapters", []):
        if "content" in chapter:
            # remove leading whitespace from each line
            chapter["content"] = re.sub(
                r"^\s+", "", chapter["content"], flags=re.MULTILINE
            )
            # remove leading/trailing whitespace from entire content
            chapter["content"] = chapter["content"].strip()
            # collapse multiple blank lines into one
            chapter["content"] = re.sub(r"\n\s*\n+", "\n\n", chapter["content"])

    def logged_in():
        return "username" in session

    log_ip(username=session.get("username"), page=request.path)

    is_admin = False
    username = session.get("username")
    if username:
        user = data["users"].get(username)
        if user and user.get("is_admin"):
            is_admin = True

    return render_template(
        "fanfic/view_fic.html", fic=fic, logged_in=logged_in(), is_admin=is_admin
    )


@app.route("/edit/<int:fid>", methods=["GET", "POST"])
def edit_fic(fid):
    global data

    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found"
    if not logged_in() or fic["owner"] != session["username"]:
        return "Unauthorized"

    all_tags = set()
    for f in data["fanfics"]:
        all_tags.update(f.get("tags", []))
    all_tags = list(all_tags)

    log_ip(username=session.get("username"), page=request.path)

    if request.method == "POST":
        selected_tags = request.form.getlist("tags")

        new_tag = request.form.get("new_tag", "").strip()

        if new_tag:
            selected_tags.append(new_tag)

        # dupes
        fic["tags"] = list(set(selected_tags))

        fic["title"] = request.form["title"]
        fic["fandom"] = request.form["fandom"]
        fic["chapters"][0]["title"] = request.form["chapter_title"]
        fic["chapters"][0]["content"] = request.form["content"]

        age_rating = request.form.get("age_rating")
        if age_rating in ["18+", "16+", "13+"]:
            fic["age_rating"] = age_rating
        else:
            # fallback or error handling if needed
            fic["age_rating"] = "13+"

        save_data()

        return redirect(url_for("view_fic", fid=fid))

    return render_template(
        "fanfic/edit_fic.html",
        fic=fic,
        data=data,
        logged_in=logged_in(),
        tags=all_tags,
        is_owner=True,
        is_admin=is_admin(),
    )


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
    global data
    if not logged_in():
        return redirect(url_for("login"))

    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found"

    content = request.form["content"]
    # convert mentions to links
    content_with_links = linkify_mentions(content)

    # get current time
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # get current user data
    user = next(
        (u for u in data["users"].values() if u["username"] == session["username"]),
        None,
    )

    print("Type of data['users']:", type(data["users"]))
    print("Data contents:", data["users"])

    # use pfp directly
    pfp_path = user["pfp"] if user and "pfp" in user and user["pfp"] else ""

    # append with pfp path
    fic["comments"].append(
        {
            "name": session["username"],
            "content": content_with_links,
            "timestamp": timestamp,
            "pfp": pfp_path,
            "user": user,
        }
    )

    # debug output
    print("Stored pfp in comment:", pfp_path)
    print("Comments' pfp paths:")
    for c in fic["comments"]:
        print(c.get("pfp", "No pfp key"))

    log_ip(username=session.get("username"), page=request.path)
    save_data()
    return redirect(url_for("fanfic/view_fic", fid=fid))


@app.route("/delete_comment/<int:fid>/<int:comment_index>", methods=["POST"])
def delete_comment(fid, comment_index):
    global data
    if not logged_in():
        return redirect(url_for("login"))

    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found"

    # is comment index valid? probably not
    if comment_index < 0 or comment_index >= len(fic["comments"]):
        return "Comment not found"

    comment = fic["comments"][comment_index]

    # debug
    current_user = session.get("username")
    is_admin = session.get("is_admin", False)

    print("Current user:", current_user)
    print("Is admin:", is_admin)
    print("Comment owner:", comment["name"])

    # check perms
    if comment["name"] != current_user and not is_admin:
        return "Unauthorized", 403

    # remove comment
    fic["comments"].pop(comment_index)

    save_data()

    # log deletion
    log_ip(username=current_user, page=request.path)

    return redirect(url_for("fanfic/view_fic", fid=fid))


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    global data
    load_banned_ips()

    current_ip = request.remote_addr
    if current_ip in banned_ips:
        return "Your IP has been banned.", 403

    username = session.get("username")
    user = None
    is_admin = False

    if username:
        user = data["users"].get(username)
        if user and user.get("is_admin"):
            is_admin = True

    if not is_admin:
        return "Access Denied", 403

    logged_in = "username" in session
    log_ip(username=session.get("username"), page=request.path)

    # prep
    user_ips = {
        uname: info.get("ip", "Unknown") for uname, info in data["users"].items()
    }

    # ban ip
    if request.method == "POST":
        ip_to_ban = request.form.get("ip")
        if ip_to_ban:
            save_banned_ip(ip_to_ban)
            return f"IP {ip_to_ban} has been banned.", 200

    # pass as list of keys
    usernames = list(data["users"].keys())

    return render_template(
        "admin/admin.html",
        fanfics=data["fanfics"],
        is_admin=True,
        user=user,
        username=username,
        session=session,
        logged_in=logged_in,
        user_ips=user_ips,
        users=data["users"],
    )


@app.route("/admin/delete_user/<username>", methods=["POST"])
def delete_user(username):
    global data
    if not is_admin():
        return "Access Denied", 403
    if username in data["users"]:
        del data["users"][username]
        save_data()

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic_admin(fic_id):
    global data
    if not is_admin():
        return "Access Denied", 403
    data["fanfics"] = [f for f in data["fanfics"] if f["id"] != fic_id]
    save_data()
    return redirect(url_for("admin_panel"))


@app.route("/ban_ip", methods=["POST"])
def ban_ip():
    if not is_admin():
        return "Unauthorized", 403
    ip_to_ban = request.form["ip"]
    save_banned_ip(ip_to_ban)
    return f"IP {ip_to_ban} has been banned."


@app.route("/ban_user/<username>", methods=["POST"])
def ban_user(username):
    global data
    if not is_admin():
        return "Unauthorized", 403
    user = get_user(username)
    if user:
        # toggle ban status
        current_status = user.get("banned", False)
        user["banned"] = not current_status
        action = "unbanned" if not user["banned"] else "banned"
        save_data()
        return f"User {username} has been {action}."
    return "User not found", 404


@app.route("/unban_user/<username>", methods=["POST"])
def unban_user(username):
    global data
    if not is_admin():
        return "Unauthorized", 403
    if username in data["users"]:
        data["users"][username]["banned"] = False
        save_data()
        return f"{username} has been unbanned."
    return "User not found", 404


@app.route("/admin/set_display_name/<username>", methods=["GET", "POST"])
def set_display_name(username):
    if not is_admin():
        return "Access denied", 403

    user = get_user(username)
    if not user:
        return "User not found", 404

    if request.method == "POST":
        new_display_name = request.form.get("display_name")
        if new_display_name:
            # ONLY set if admin
            if user.get("is_admin"):
                # prepend mod to display name
                user["display_name"] = "Mod " + new_display_name
                save_user(user)
                return redirect(url_for("profile", username=username))
            else:
                return "Cannot set display name for non-admin users.", 403
        else:
            error = "Please enter a display name."
            return render_template("set_display_name.html", user=user, error=error)

    if "display_name" not in user:
        user["display_name"] = user["username"]
    return render_template(
        "admin/set_display_name.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/kudo/<int:fid>", methods=["POST"])
def add_kudo(fid):
    global data
    if not logged_in():
        return redirect(url_for("login"))
    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)

    if fic is None:
        abort(404)

    user = session["username"]
    if user not in fic["kudos"]:
        fic["kudos"].append(user)

        # log ip
        log_ip(username=session.get("username"), page=request.path)

        save_data()

    return redirect(url_for("fanfic/view_fic", fid=fid))


@app.route("/notes")
def notes():
    global data
    if not logged_in():
        return redirect(url_for("login"))
    username = session["username"]
    user = get_user(username)
    if not user:
        return "User not found", 404

    log_ip(username=username, page=request.path)

    all_notes = data.get("notes", {})

    user_notes = {
        note_id: note
        for note_id, note in all_notes.items()
        if isinstance(note, dict) and note.get("owner") == username
    }

    notes_with_ids = [
        {"id": note_id, "content": note.get("content", "")}
        for note_id, note in user_notes.items()
    ]

    # vodka
    page = int(request.args.get("page", 1))
    per_page = 10

    total_posts = len(notes_with_ids)
    total_pages = (total_posts + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    display_notes = notes_with_ids[start:end]

    return render_template(
        "notes/notes.html",
        notes=display_notes,
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
    global data
    if not logged_in():
        return redirect(url_for("login"))
    username = session["username"]
    user = get_user(username)
    if not user:
        return "User not found", 404

    # use global data
    all_notes = data.get("notes", {})

    log_ip(username=session.get("username"), page=request.path)

    # forgot
    note_value = all_notes.get(str(note_id))
    print("Raw note value:", note_value)
    if not note_value:
        return "Note not found", 404

    # d etermination
    if isinstance(note_value, str):
        try:
            note = json.loads(note_value)
            print("Note after json.loads:", note)
        except json.JSONDecodeError:
            note = {"content": note_value}
            print("JSON decode error, using raw string as content:", note)
    elif isinstance(note_value, dict):
        note = note_value
        print("Note is already a dict:", note)
    else:
        return "Invalid note data format", 500

    # verification
    print("Note owner:", note.get("owner"))
    if note.get("owner") != username:
        return "Unauthorized", 403

    # extraction
    note_content = note.get("content")
    print("Note content to display:", note_content)

    return render_template(
        "notes/view_note.html",
        note_id=note_id,
        note_content=note_content,
        user=user,
        logged_in=True,
        session=session,
        is_owner=True,
        is_admin=is_admin(),
    )


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    global data
    if not logged_in():
        return redirect(url_for("login"))

    username = session.get("username")
    user = get_user(username) if username else None

    if request.method == "POST":
        log_ip(username=session.get("username"), page=request.path)

        # note id
        try:
            max_id = max([int(k) for k in data.get("notes", {}).keys()])
        except ValueError:
            max_id = 0
        note_id = str(max_id + 1)

        content = request.form["content"]

        sanitized_content = sanitize_note_content(content)

        if "notes" not in data:
            data["notes"] = {}

        data["notes"][note_id] = {"owner": username, "content": sanitized_content}

        save_data()

        return redirect(url_for("view_note", note_id=note_id))
    return render_template(
        "notes/new_note.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/notes/<note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    global data
    note = data["notes"].get(str(note_id))
    if note is None:
        print(f"Note with ID {note_id} not found.")
        abort(404)

    if note.get("owner") != session.get("username"):
        print(f"User {session.get('username')} unauthorized to edit note {note_id}")
        abort(403)

    log_ip(username=session.get("username"), page=request.path)

    if request.method == "POST":
        if request.form.get("delete"):
            # delete
            del data["notes"][str(note_id)]
            save_data()
            return redirect(url_for("notes"))
        else:
            new_content = request.form.get("content")
            if not new_content:
                return render_template(
                    "edit_note.html",
                    content=note["content"],
                    note_id=note_id,
                    error="Content cannot be empty",
                    delete_button=False,
                    is_admin=is_admin(),
                    logged_in=logged_in(),
                )

            # bleach
            sanitized_content = sanitize_note_content(new_content)
            note["content"] = sanitized_content
            save_data()
            return redirect(url_for("view_note", note_id=note_id))
    else:
        return render_template(
            "notes/edit_note.html",
            content=note["content"],
            note_id=note_id,
            delete_button=False,
            is_admin=is_admin(),
            logged_in=logged_in(),
        )


@app.route("/blog")
def blog():
    global data
    blog_posts = data.get("blog_posts", {})

    # sort posts by timestamp descending
    posts = []
    for post_id, post in blog_posts.items():
        author_username = post["author"]
        user = get_user(author_username)

        if user:
            display_name = user.get("display_name", author_username)
        else:
            display_name = author_username

        posts.append(
            {
                "id": post_id,
                "title": post["title"],
                "content": post["content"],
                "author": display_name,
                "timestamp": post["timestamp"],
                "formatted_timestamp": datetime.fromisoformat(
                    post["timestamp"]
                ).strftime("%B %d, %Y at %I:%M %p"),
            }
        )

    posts.sort(key=lambda x: x["timestamp"], reverse=True)
    print(f"Number of posts in list: {len(posts)}")

    #  BEER
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
    global data
    post = data.get("blog_posts", {}).get(post_id)
    if not post:
        return "Post not found", 404

    post["formatted_timestamp"] = datetime.fromisoformat(post["timestamp"]).strftime(
        "%B %d, %Y at %I:%M %p"
    )

    return render_template(
        "view_blog_post.html",
        post=post,
        post_id=post_id,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/blog/new", methods=["GET", "POST"])
def new_blog_post():
    global data
    if not logged_in():
        return redirect(url_for("login"))

    username = session.get("username")
    user = get_user(username) if username else None
    # admin check
    if not user or not user.get("is_admin", False):
        return "Unauthorized: Admins only", 403

    if request.method == "POST":
        # generate a new post id
        post_id = str(
            max([int(k) for k in data.get("blog_posts", {}).keys()] or [0]) + 1
        )
        title = request.form["title"]
        content = request.form["content"]
        display_name = user.get("display_name", username)

        if "blog_posts" not in data:
            data["blog_posts"] = {}
        data["blog_posts"][post_id] = {
            "title": title,
            "content": content,
            "author": display_name,
            "timestamp": datetime.now().isoformat(),
        }

        save_data()
        return redirect(url_for("view_blog_post", post_id=post_id))
    return render_template(
        "admin/new_blog_post.html",
        user=user,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/blog/<post_id>/edit", methods=["GET", "POST"])
def edit_blog_post(post_id):
    global data

    post = data.get("blog_posts", {}).get(post_id)
    if not post:
        return "Post not found", 404

    # check if user logged in
    username = session.get("username")
    user = get_user(username) if username else None

    if not user or not user.get("is_admin", False):
        return "Unauthorized: Admins only", 403

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        post["title"] = title
        post["content"] = content
        post["timestamp"] = datetime.now().isoformat()

        save_data()
        return redirect(url_for("view_blog_post", post_id=post_id))
    else:
        return render_template(
            "admin/edit_blog_post.html",
            post=post,
            post_id=post_id,
            is_admin=is_admin(),
            logged_in=logged_in(),
        )


# i kinda give up on comments sorry
@app.route("/blog/<post_id>/delete", methods=["POST"])
def delete_blog_post(post_id):
    global data

    post = data.get("blog_posts", {}).get(post_id)
    if not post:
        return "Post not found", 404

    username = session.get("username")
    user = get_user(username) if username else None

    if not user or not user.get("is_admin", False):
        return "Unauthorized: Admins only", 403

    del data["blog_posts"][post_id]

    save_data()

    return redirect(url_for("blog"))


@app.route("/about")
def about():
    global data

    return render_template(
        "about.html",
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/site-info", methods=["GET", "POST"])
def edit_site_info():
    global data
    site_info = data.get("site_info", {})

    if request.method == "POST":
        # get updated info from form
        title = request.form.get("title")
        content = request.form.get("content")
        data["site_info"] = {"title": title, "content": content}
        save_data()
        return redirect(url_for("about"))

    return render_template(
        "admin/edit_site_info.html",
        site_info=site_info,
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
    users_list = list(data["users"].keys())

    return render_template(
        "admin/logs.html",
        logs=data["ip_logs"],
        user_logs=data.get("user_logs", {}),
        username=username,
        users=users_list,
        is_admin=is_admin(),
        logged_in=logged_in(),  # pass the list not a dict
    )


@app.route("/admin/all_logs")
def all_logs():
    user_logs = data.get("user_logs", {})
    all_logs_combined = []

    for username, logs in user_logs.items():
        for log in logs:
            # add username info if not already in log
            if "username" not in log:
                log["username"] = username
            all_logs_combined.append(log)

    return render_template(
        "admin/all_logs.html",
        logs=all_logs_combined,
        is_admin=is_admin(),
        logged_in=logged_in(),
    )


@app.route("/admin/logs/<username>")
def user_logs(username):
    user_logs = data.get("user_logs", {}).get(username, [])  # default to empty list
    users = list(data["users"].keys())
    return render_template(
        "admin/user_logs.html",
        user_logs=user_logs,
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
    app.run(debug=True)
