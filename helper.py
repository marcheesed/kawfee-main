import bcrypt
import json

# Load your data
data_file = "data.json"
with open(data_file, "r") as f:
    data = json.load(f)

# Loop through all users
for username, user_data in data["users"].items():
    password = user_data["password"]
    # Check if password is already hashed
    if not (password.startswith("$2b$") or password.startswith("$2a$")):
        # Hash the plain text password
        new_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        # Update the password
        user_data["password"] = new_hash
        print(f"Updated password for {username} to bcrypt hash: {new_hash}")

# Save the data back
with open(data_file, "w") as f:
    json.dump(data, f, indent=4)
