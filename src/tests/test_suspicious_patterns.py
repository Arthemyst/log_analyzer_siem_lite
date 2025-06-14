from datetime import datetime

from src.suspicious_patterns import parse_time


def test_parsing_log_with_time():
    logs = "2025 Jun 11 11:00:01 server sshd[11111]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2"

    time_match = parse_time(logs)
    assert (datetime(2025, 6, 11, 11, 0, 1) == time_match)


def test_parsing_log_without_time():
    logs = "No data to parse"

    time_match = parse_time(logs)
    assert (time_match is None)
