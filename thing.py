import calendar
import datetime
import gzip
import os
import shutil
import sqlite3
import time

import requests  # install via: pip install requests

# --- CONFIGURATION ---
DB_PATH = "new.db"
BACKUP_DIR = "backups"
MONTHLY_DIR = "backups/monthly"
KEEP_DAYS = 120  # keep 4 months
CHECK_INTERVAL = 3600  # check every hour
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1436020123403026553/05ndMdljy9UpyjOQUaHAMeBFVeR8JeJGQcC-4khiQR71BbUQ1Hz0Czowcv14DQTyfhg0"
PING_USER_IDS = [
    "1175237222384017448",
    "410137614591459328",
    "814532209385799680",
]  # personal amy and main


def send_discord_alert(message: str):
    """Send a message to Discord via webhook."""
    if not DISCORD_WEBHOOK:
        print("No Discord webhook configured.")
        return

    # add mentions if any user IDs are listed
    if PING_USER_IDS:
        mentions = " ".join(f"<@{uid}>" for uid in PING_USER_IDS)
        message = f"{mentions} {message}"

    try:
        requests.post(DISCORD_WEBHOOK, json={"content": message})
    except Exception as e:
        print(f" Failed to send Discord alert: {e}")


def create_backup():
    """Create a daily backup, compress it, and handle monthly archives."""
    today = datetime.date.today()
    backup_file = os.path.join(BACKUP_DIR, f"mydb_{today}.db")
    compressed_file = backup_file + ".gz"

    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(MONTHLY_DIR, exist_ok=True)

    if os.path.exists(compressed_file):
        print(f"Backup for {today} already exists.")
        return

    try:
        print(f"Creating backup for {today}...")
        with sqlite3.connect(DB_PATH) as src, sqlite3.connect(backup_file) as dst:
            src.backup(dst)
        time.sleep(1)  # let Windows release file handle

        print(f"Compressing {backup_file}...")
        with open(backup_file, "rb") as f_in, gzip.open(compressed_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(backup_file)
        print(f"Backup complete: {compressed_file}")

        # If last day of month → make archive
        if is_last_day_of_month(today):
            archive_file = os.path.join(
                MONTHLY_DIR, f"mydb_{today:%Y-%m-%d}_monthly.db"
            )
            print(f"Creating monthly archive: {archive_file}")
            with sqlite3.connect(DB_PATH) as src, sqlite3.connect(archive_file) as dst:
                src.backup(dst)
            print("Monthly archive created.")
            send_discord_alert(f"Monthly archive created: `{archive_file}`")

        # Cleanup
        cleanup_old_backups()

        # Send success message
        send_discord_alert(
            f"SQLite backup successful for `{today}` — saved `{compressed_file}`"
        )

    except Exception as e:
        err_msg = f" SQLite backup failed on {today}: {e}"
        print(err_msg)
        send_discord_alert(err_msg)


def cleanup_old_backups():
    """Delete old backups beyond KEEP_DAYS."""
    now = datetime.datetime.now()
    for fname in os.listdir(BACKUP_DIR):
        fpath = os.path.join(BACKUP_DIR, fname)
        if os.path.isfile(fpath):
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
            if (now - mtime).days > KEEP_DAYS:
                os.remove(fpath)
                print(f"Removed old backup: {fname}")


def is_last_day_of_month(date_obj):
    """Return True if the date is the last day of its month."""
    _, last_day = calendar.monthrange(date_obj.year, date_obj.month)
    return date_obj.day == last_day


if __name__ == "__main__":
    print("SQLite daily snapshot service started.")
    send_discord_alert("Backup service started and running.")
    while True:
        try:
            create_backup()
        except Exception as e:
            err_msg = f"Fatal error in backup loop: {e}"
            print(err_msg)
            send_discord_alert(err_msg)
        time.sleep(CHECK_INTERVAL)
