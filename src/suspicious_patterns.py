import re
from datetime import datetime


def parse_time(line):
    time_match = re.match(r"^(\d{4}\s+\w+\s+\d+\s+\d+:\d+:\d+)", line)

    if time_match:
        try:
            return datetime.strptime(time_match.group(1), "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
        return None
