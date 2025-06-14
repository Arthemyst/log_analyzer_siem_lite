import re
from collections import defaultdict
from datetime import datetime, timedelta


def parse_time(line):
    time_match = re.match(r"^(\d{4}\s+\w+\s+\d+\s+\d+:\d+:\d+)", line)

    if time_match:
        try:
            return datetime.strptime(time_match.group(1), "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
        return None


def detect_suspicious_entries(log_lines: list, brute_force_threshold: int = 5, brute_force_window: int = 120) -> list:
    alerts = []
    failed_logins = defaultdict(list)

    for log_line in log_lines:
        log_line = log_line.strip()
        log_time = parse_time(log_line)
        if not log_time:
            continue
        if "Failed password" in log_line:
            text_match = re.search(r"Failed password for (invalid user )?(\w+)", log_line)
            if text_match:
                login = text_match.group(2)
                alerts.append(("Failed login attempt", log_line))

                # Brute-force analyse
                failed_logins[login].append(log_time)
                window_start = log_time - timedelta(seconds=brute_force_window)
                recent = [time for time in failed_logins[login] if time >= window_start]
                failed_logins[login] = recent

                if len(recent) == brute_force_threshold:
                    alerts.append((
                        "Brute-force pattern detected",
                        f"{brute_force_threshold}+ failed attempts for '{login}' within {brute_force_window} seconds.\n\tExample: {log_line}"
                    ))

        # root login
        if re.search(r"Accepted password.*root", log_line):

            alerts.append(("Root login detected", log_line.strip()))

    return alerts
