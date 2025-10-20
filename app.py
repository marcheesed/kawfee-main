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
import datetime
from typing import Any

note: Any = None

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a real secret

DATA_FILE = "data.json"

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
]


def sanitize_bio(html_content):
    return bleach.clean(
        html_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True
    )


def load_data():
    with open(DATA_FILE, "r") as f:
        return json.load(f)


data = load_data()  # This should be a dict


def log_ip():
    ip = request.remote_addr
    timestamp = datetime.datetime.now().isoformat()
    with open("ip_logs.txt", "a") as f:
        f.write(f"{timestamp} - IP: {ip}\n")


banned_ips = set()


# Load from a file
def load_banned_ips():
    try:
        with open("banned_ips.txt", "r") as f:
            for line in f:
                banned_ips.add(line.strip())
    except FileNotFoundError:
        pass


# Save to a file
def save_banned_ip(ip):
    with open("banned_ips.txt", "a") as f:
        f.write(ip + "\n")
    banned_ips.add(ip)


def load_users():
    global data
    return data


def save_users(updated_data):
    global data
    data = updated_data

    # Define save_data function outside or before the route
    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

    # Call save_data after updating
    save_data(data)


# Save data to json
def save_data():
    global data
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


# Helper to check login status
def logged_in():
    return "username" in session


def get_user(username):
    return data["users"].get(username)


# check if admin
def is_admin():
    if not logged_in():
        return False
    username = session["username"]
    user_info = data["users"].get(username)
    print("User info:", user_info)  # Debug
    if isinstance(user_info, dict):  # Check if it's a dict
        return user_info.get("is_admin", False)
    return False


def save_user(user):
    data = load_users()
    old_username = user.get(
        "old_username", user["username"]
    )  # If username changed, handle it
    data["users"][old_username] = user
    # If username changed, remove old key
    if old_username != user["username"]:
        del data["users"][old_username]
    save_users(data)


@app.before_request
def check_ban():
    load_banned_ips()  # Load the list each request or once during startup
    ip = request.remote_addr
    if ip in banned_ips:
        return "Your IP has been banned.", 403


# Home page
@app.route("/")
def index():
    search_query = request.args.get("search", "").lower()
    filter_tag = request.args.get("tag", "")

    # Access fanfics list
    fanfics_list = data["fanfics"]

    # Filter based on search
    filtered_fanfics = fanfics_list
    if search_query:
        filtered_fanfics = [
            f
            for f in fanfics_list
            if search_query in f["title"].lower() or search_query in f["author"].lower()
        ]

    # Filter by tag
    if filter_tag:
        filtered_fanfics = [f for f in filtered_fanfics if filter_tag in f["tags"]]

    # Collect all tags for display
    all_tags = set()
    for f in fanfics_list:
        all_tags.update(f["tags"])

    # Determine admin status
    admin_status = is_admin()

    return render_template(
        "index.html",
        fanfics=filtered_fanfics,
        all_tags=sorted(all_tags),
        current_tag=filter_tag,
        search_query=request.args.get("search", ""),
        logged_in=logged_in(),
        is_admin=admin_status,  # pass this to the template
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in data["users"]:
            return "Username already exists!"

        # Capture the IP address
        ip_address = request.remote_addr

        # Add user with additional info: ip
        data["users"][username] = {
            "password": password,
            "is_admin": False,
            "bio": "",
            "ip": ip_address,  # Save IP here
        }

        # Define save_data function outside or before the route
        def save_data(data):
            with open("data.json", "w") as f:
                json.dump(data, f)

        # Call save_data after updating
        save_data(data)
        session["username"] = username
        return redirect(url_for("index"))

    # For GET request, render the registration form
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
        user = get_user(username)
        print("Fetched user:", user)  # Debug

        if not user:
            return "User not found", 404

        # Check if user is banned
        if user.get("banned"):
            return "This user has been banned.", 403

        # Verify credentials
        if (
            username in data["users"]
            and data["users"][username]["password"] == password
        ):
            # Save IP address to user data
            ip_address = request.remote_addr
            if username in data["users"]:
                data["users"][username]["ip"] = ip_address

            session["username"] = username
            return redirect(url_for("index"))
        else:
            return "Invalid credentials"

    # For GET request, prepare variables for rendering the template
    logged_in = "username" in session
    if logged_in:
        username = session["username"]
        user = get_user(username)
        admin_status = is_admin()

    return render_template(
        "login.html",
        username=username,
        session=session,
        logged_in=logged_in,
        user=user,
        is_admin=admin_status,
    )


# Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


@app.route("/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic(fic_id):
    global data
    with open(DATA_FILE, "r") as f:
        data = json.load(f)
    # Remove the fic with matching id
    data["fanfics"] = [fic for fic in data["fanfics"] if fic["id"] != fic_id]

    # Define save_data function outside or before the route
    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

    # Call save_data after updating
    save_data(data)
    return redirect(url_for("profile"))


@app.route("/add_tag", methods=["POST"])
def add_tag():
    data = request.get_json()
    new_tag = data.get("tag", "").strip()

    if not new_tag:
        return jsonify({"success": False, "error": "No tag provided"}), 400

    # Load existing tags from tags.json
    try:
        with open("tags.json", "r") as f:
            tags = json.load(f)
    except FileNotFoundError:
        tags = []

    # Check if the tag already exists
    if new_tag in tags:
        return jsonify({"success": True, "message": "Tag already exists"})

    # Add new tag
    tags.append(new_tag)

    # Write back to tags.json
    with open("tags.json", "w") as f:
        json.dump(tags, f)

    return jsonify({"success": True, "tag": new_tag})


@app.route("/profile/<username>")
def user_profile(username):
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
    return render_template(
        "profile.html",
        fanfics=user_fanfics,
        username=username,
        session=session,
        logged_in=logged_in,
        user=user,
        is_owner=is_owner,
        is_admin=admin_status,
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

    # Load your data.json
    with open("data.json", "r") as f:
        data = json.load(f)

    # Extract notes
    notes_data = data.get("notes", {})

    # Add username to user data
    user["username"] = username
    admin_status = is_admin()

    # Filter fanfics
    user_fanfics = [fic for fic in data["fanfics"] if fic["owner"] == username]

    # Determine if the logged-in user is viewing their own profile
    is_owner = True  # Change if supporting other profiles

    return render_template(
        "profile.html",
        fanfics=user_fanfics,
        notes=notes_data,  # Pass notes to the profile template
        username=username,
        session=session,
        logged_in=is_logged_in,
        user=user,
        is_owner=is_owner,
        is_admin=admin_status,
    )


@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    print("edit_profile route hit")
    logged_in = "username" in session
    if not logged_in:
        return redirect(url_for("login"))

    old_username = session["username"]
    user = get_user(old_username)
    if not user:
        return "User not found", 404

    if request.method == "POST":
        # Get form data
        new_username = request.form.get("username").strip()
        new_bio_raw = request.form.get("bio", "")
        pfp_file = request.files.get("pfp")
        new_custom_css = request.form.get("custom_css")

        # Sanitize bio
        new_bio_raw = request.form.get("bio", "")
        # Strip whitespace
        new_bio_raw = new_bio_raw.strip()
        new_bio = sanitize_bio(new_bio_raw)

        # Handle profile picture upload
        if pfp_file and pfp_file.filename != "":
            filename = secure_filename(pfp_file.filename)
            upload_dir = os.path.join(app.static_folder, "pfps")
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)
            print("Saving file to:", upload_path)  # Debug
            pfp_file.save(upload_path)
            user["pfp"] = f"pfps/{filename}"
            print("Stored image path:", user["pfp"])  # Debug

        # Check if username changed
        if new_username != old_username:
            # Move user data to new key
            data["users"][new_username] = data["users"].pop(old_username)
            # Update session username
            session["username"] = new_username

            # Update all fanfics owned and authored by that user
            for fic in data["fanfics"]:
                if fic["owner"] == old_username:
                    fic["owner"] = new_username
                if fic["author"] == old_username:
                    fic["author"] = new_username

        # Update user data
        user = get_user(new_username)  # get the updated user object after moving
        user["username"] = new_username
        user["bio"] = new_bio
        user["custom_css"] = new_custom_css

        # Save user data
        save_user(user)

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

    # Load data.json
    with open("data.json", "r") as f:
        data = json.load(f)

    # Get tags from data.json
    tags = data.get("tags", [])

    if request.method == "POST":
        # Generate new ID
        new_id = max([f["id"] for f in data["fanfics"]], default=0) + 1

        import re

        # Get raw content
        content_raw = request.form.get("content", "")
        # Normalize: remove extra blank lines and trim
        content_raw = re.sub(r"\n+", "\n", content_raw.strip())

        # Debug: print normalized content before saving
        print("Normalized content before saving:", repr(content_raw))

        chapter_title_raw = request.form.get("chapter_title", "").strip()

        # Get tags
        selected_tags = request.form.getlist("tags")
        new_tag = request.form.get("new_tag", "").strip()

        combined_tags = list(set(selected_tags))
        if new_tag:
            combined_tags.append(new_tag)

        # Create new fanfic object
        new_fic = {
            "id": new_id,
            "title": request.form["title"],
            "author": session["username"],
            "owner": session["username"],
            "fandom": request.form["fandom"],
            "stats": {"words": 0, "chapters": 1, "kudos": 0},
            "tags": combined_tags,
            "chapters": [
                {
                    "title": chapter_title_raw,
                    "content": content_raw,
                }
            ],
            "comments": [],
            "kudos": [],
        }

        # Append to data and save
        data["fanfics"].append(new_fic)
        print(
            "Data before saving:", repr(data["fanfics"][-1]["chapters"][0]["content"])
        )

        # Save data back to data.json
        def save_data(data):
            with open("data.json", "w") as f:
                json.dump(data, f)

        save_data(data)

        return redirect(url_for("view_fic", fid=new_fic["id"]))

    return render_template(
        "submit.html",
        data=data,
        logged_in=logged_in(),
        tags=tags,
        is_admin=is_admin(),
    )


@app.route("/fic/<int:fid>")
def view_fic(fid):
    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found", 404

    # Normalize each chapter's content
    for chapter in fic.get("chapters", []):
        if "content" in chapter:
            # Remove leading whitespace from each line
            chapter["content"] = re.sub(
                r"^\s+", "", chapter["content"], flags=re.MULTILINE
            )
            # Remove leading/trailing whitespace from entire content
            chapter["content"] = chapter["content"].strip()
            # Collapse multiple blank lines into one
            chapter["content"] = re.sub(r"\n\s*\n+", "\n\n", chapter["content"])

    # Check if user is logged in
    def logged_in():
        return "username" in session

    # Determine if current user is admin
    is_admin = False
    username = session.get("username")
    if username:
        user = data["users"].get(username)
        if user and user.get("is_admin"):
            is_admin = True

    return render_template(
        "view_fic.html", fic=fic, logged_in=logged_in(), is_admin=is_admin
    )


# Edit fanfic
@app.route("/edit/<int:fid>", methods=["GET", "POST"])
def edit_fic(fid):
    global data
    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found"
    if not logged_in() or fic["owner"] != session["username"]:
        return "Unauthorized"

    # Load all tags
    all_tags = set()
    for f in data["fanfics"]:
        all_tags.update(f["tags"])

    if request.method == "POST":
        # Your existing POST handling code...
        # ...
        return redirect(url_for("view_fic", fid=fid))
    return render_template(
        "edit.html", fic=fic, data=data, logged_in=logged_in(), tags=all_tags
    )


# Add comment
@app.route("/comment/<int:fid>", methods=["POST"])
def add_comment(fid):
    global data
    if not logged_in():
        return redirect(url_for("login"))
    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    if not fic:
        return "Fanfic not found"
    fic["comments"].append(
        {"name": session["username"], "content": request.form["content"]}
    )

    # Define save_data function outside or before the route
    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

    # Call save_data after updating
    save_data(data)
    return redirect(url_for("view_fic", fid=fid))


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    # Load banned IPs
    load_banned_ips()

    # Check if current IP is banned
    current_ip = request.remote_addr
    if current_ip in banned_ips:
        return "Your IP has been banned.", 403

    # Determine if current user is admin
    username = session.get("username")
    user = None
    is_admin = False

    if username:
        user = data["users"].get(username)
        if user and user.get("is_admin"):
            is_admin = True

    if not is_admin:
        return "Access Denied", 403

    # Check if logged in
    logged_in = "username" in session

    # Prepare user IPs
    user_ips = {
        uname: info.get("ip", "Unknown") for uname, info in data["users"].items()
    }

    # Check if a POST request to ban an IP
    if request.method == "POST":
        ip_to_ban = request.form.get("ip")
        if ip_to_ban:
            save_banned_ip(ip_to_ban)
            return f"IP {ip_to_ban} has been banned.", 200

    # Pass list of usernames (keys)
    usernames = list(data["users"].keys())

    return render_template(
        "admin.html",
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
    if not is_admin():
        return "Access Denied", 403
    if username in data["users"]:
        del data["users"][username]

    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_fic/<int:fic_id>", methods=["POST"])
def delete_fic_admin(fic_id):
    if not is_admin():
        return "Access Denied", 403
    data["fanfics"] = [f for f in data["fanfics"] if f["id"] != fic_id]

    def save_data(data):
        with open("data.json", "w") as f:
            json.dump(data, f)

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
    if not is_admin():
        return "Unauthorized", 403
    user = get_user(username)
    if user:
        # Toggle ban status
        current_status = user.get("banned", False)
        user["banned"] = not current_status
        action = "unbanned" if not user["banned"] else "banned"
        return f"User {username} has been {action}."
    return "User not found", 404


@app.route("/unban_user/<username>", methods=["POST"])
def unban_user(username):
    if not is_admin():
        return "Unauthorized", 403
    if username in data["users"]:
        data["users"][username]["banned"] = False
        return f"{username} has been unbanned."
    return "User not found", 404


# Add kudos
@app.route("/kudo/<int:fid>", methods=["POST"])
def add_kudo(fid):
    global data
    if not logged_in():
        return redirect(url_for("login"))
    fic = next((f for f in data["fanfics"] if f["id"] == fid), None)
    user = session["username"]
    if user not in fic["kudos"]:
        fic["kudos"].append(user)

        def save_data(data):
            with open("data.json", "w") as f:
                json.dump(data, f)

    return redirect(url_for("view_fic", fid=fid))


@app.route("/notes")
def notes():
    is_logged_in = logged_in()
    if not is_logged_in:
        return redirect(url_for("login"))
    username = session["username"]
    user = get_user(username)
    if not user:
        return "User not found", 404

    # Load your data.json
    with open("data.json", "r") as f:
        data = json.load(f)

    # Assuming notes are stored under data["notes"]
    notes_data = data.get("notes", {})

    # Pass notes_data to the template
    return render_template(
        "notes.html",
        notes=notes_data,
        username=username,
        session=session,
        logged_in=is_logged_in,
        user=user,
        is_owner=True,
        is_admin=is_admin(),
    )


@app.route("/notes/<note_id>")
def view_note(note_id):
    # Fetch the note directly from the dictionary by string key
    note = data["notes"].get(str(note_id))
    if not note:
        abort(404)

    # Handle if note is a string or a dictionary
    if isinstance(note, str):
        note_content = note
    elif isinstance(note, dict):
        note_content = note.get("content", "")
    else:
        # Unexpected data type
        abort(500)

    # Normalize whitespace
    import re

    note_content = re.sub(r"\n\s*\n+", "\n\n", note_content)

    # Prepare context data (replace with actual user info and login status)
    context = {
        "user": "example_user",  # Replace with actual user info
        "logged_in": True,  # Replace with actual login status
        "notes": data["notes"],
    }

    return render_template(
        "view_note.html",
        note_id=note_id,
        note=note_content,
        user=context["user"],
        notes=context["notes"],
        logged_in=context["logged_in"],
    )


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    is_logged_in = logged_in()
    if not is_logged_in:
        return redirect(url_for("login"))
    # Retrieve the user info
    username = session.get("username")
    user = get_user(username) if username else None

    if request.method == "POST":
        data = load_data()
        note_id = str(
            max([int(k) for k in data.get("notes", {}).keys()], default=0) + 1
        )
        # Get raw text content from form
        content = request.form["content"]
        # Ensure the notes dictionary exists
        if "notes" not in data:
            data["notes"] = {}
        # Save the plain text content directly
        data["notes"][note_id] = content

        # Define save_data function outside or before the route
        def save_data(data):
            with open("data.json", "w") as f:
                json.dump(data, f)

        # Call save_data after updating
        save_data(data)

        return redirect(url_for("view_note", note_id=note_id))
    return render_template("new_note.html", user=user)


# Route to edit a note


@app.route("/notes/<note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    # Fetch the note; note_id is a string key
    note = data["notes"].get(str(note_id))
    if not note:
        abort(404)

    if request.method == "POST":
        # Get updated note content from form
        new_content = request.form.get("content")
        if new_content is None:
            # Handle error or re-render form with error message
            return render_template(
                "edit_note.html", note=note, error="Content cannot be empty"
            )
        # Save the updated content
        # If the note is a string
        if isinstance(note, str):
            data["notes"][str(note_id)] = new_content
        elif isinstance(note, dict):
            note["content"] = new_content
        else:
            abort(500)
        # Redirect back to the note view page after saving
        return redirect(url_for("view_note", note_id=note_id))
    else:
        # Render the edit form
        return render_template("edit_note.html", note=note)


def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)


@app.template_filter("nl2br")
def nl2br_filter(s):
    if s is None:
        return ""
    return s.replace("\n", "<br>\n")


if __name__ == "__main__":
    app.run(debug=True)
