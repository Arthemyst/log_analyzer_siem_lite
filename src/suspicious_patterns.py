import re
from datetime import datetime

from . import db

db.init_db()


def parse_time(line: str) -> datetime | None:
    time_match = re.match(r"^(\d{4}\s+\w+\s+\d+\s+\d+:\d+:\d+)", line)

    if time_match:
        try:
            return datetime.strptime(time_match.group(1), "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
        return None
    return None


def detect_suspicious_entries(log_lines: list, brute_force_threshold: int = 5, brute_force_window: int = 120) -> list:
    alerts = []

    for log_line in log_lines:
        log_line = log_line.strip()
        if not log_line:
            continue
        log_time = parse_time(log_line)
        if not log_time:
            continue
        if "Failed password" in log_line:
            text_match = re.search(r"Failed password for (?:invalid user )?(\w+)", log_line)
            if text_match:
                username = text_match.group(1)
                alerts.append(("Failed login attempt", log_line))
                db.add_failed_login(username, datetime.now())

                # Brute-force analyse
                recent = db.get_recent_attempts(username, brute_force_window)
                if len(recent) == brute_force_threshold:
                    alerts.append((
                        "Brute-force pattern detected",
                        f"{brute_force_threshold}+ failed attempts for '{username}' within {brute_force_window} seconds.\n\tExample: {log_line}"
                    ))

        # root login
        if re.search(r"Accepted password.*root", log_line):
            alerts.append(("Root login detected", log_line.strip()))

    db.cleanup_old_entries()
    return alerts
