import re
from datetime import datetime

from . import failed_logins

failed_logins.init_db()


def parse_time(line: str) -> datetime | None:
    time_match = re.match(r"^(\d{4}\s+\w+\s+\d+\s+\d+:\d+:\d+)", line)

    if time_match:
        try:
            return datetime.strptime(time_match.group(1), "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
        return None
    return None


def detect_suspicious_entries(log_lines: list, brute_force_threshold: int = 5, brute_force_window: int = 120, min_alert_interval: int = 30) -> list:
    alerts = []
    last_alert_time: dict[str, datetime] = {}

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
                failed_logins.add_failed_login(username, datetime.now())

                recent = failed_logins.get_recent_attempts(username, brute_force_window)
                attempts = len(recent)

                if attempts  >= brute_force_threshold:
                    now = datetime.now()
                    last_alert = failed_logins.get_last_alert_time(username)
                    if not last_alert or (now - last_alert).total_seconds() > min_alert_interval:
                        alerts.append((
                            "Brute-force pattern detected",
                            f"{brute_force_threshold}+ failed attempts for '{username}' within {brute_force_window} seconds.\n\tExample: {log_line}"
                        ))
                        failed_logins.update_last_alert_time(username, now)

        if re.search(r"Accepted password.*root", log_line):
            alerts.append(("Root login detected", log_line.strip()))

    failed_logins.cleanup_old_entries()
    return alerts
