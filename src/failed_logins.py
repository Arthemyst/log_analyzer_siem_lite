import os
import sqlite3
from datetime import datetime
from typing import List

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cache", "failed_logins.db")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts_log (
            username TEXT PRIMARY KEY,
            last_alert_time TEXT
        )
    """)

    conn.commit()
    conn.close()


def add_failed_login(username: str, timestamp: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO failed_logins (username, timestamp) VALUES (?, ?)",
            (username, timestamp.isoformat())
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_attempts(username: str, window_seconds: int) -> List[datetime]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cutoff_dt = datetime.now() - __import__("datetime").timedelta(seconds=window_seconds)
        cur.execute(
            "SELECT timestamp FROM failed_logins WHERE username = ? AND timestamp >= ?",
            (username, cutoff_dt.isoformat())

        )
        rows = cur.fetchall()
        return [datetime.fromisoformat(r[0]) for r in rows]
    finally:
        conn.close()


def cleanup_old_entries(older_than_seconds: int = 600) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cutoff_dt = datetime.now() - __import__("datetime").timedelta(seconds=older_than_seconds)
        cur.execute("DELETE FROM failed_logins WHERE timestamp < ?", (cutoff_dt.isoformat(),))
        conn.commit()
    finally:
        conn.close()


def get_last_alert_time(username: str) -> datetime | None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("SELECT last_alert_time FROM alerts_log WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None
    finally:
        conn.close()


def update_last_alert_time(username: str, timestamp: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO alerts_log (username, last_alert_time)
            VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET last_alert_time = excluded.last_alert_time
        """, (username, timestamp.isoformat()))
        conn.commit()
    finally:
        conn.close()