from datetime import datetime

from src.suspicious_patterns import parse_time, detect_suspicious_entries


def test_parsing_log_with_time():
    logs = "2025 Jun 11 11:00:01 server sshd[11111]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2"

    time_match = parse_time(logs)
    assert (datetime(2025, 6, 11, 11, 0, 1) == time_match)


def test_parsing_log_without_time():
    logs = "No data to parse"

    time_match = parse_time(logs)
    assert (time_match is None)


def test_parsing_log_with_wrong_time_format():
    logs = [
        "11:00:01 2025 Jun 11 server sshd[11111]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2",
        "Jun 11 11:00:01 server sshd[11111]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2"]
    for log in logs:
        time_match = parse_time(log)
        assert (time_match is None)


def test_failed_login_detection():
    logs = [
        "2025 Jun 11 11:00:01 server sshd[11111]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2"
    ]
    alerts = detect_suspicious_entries(logs)
    assert any("Failed login attempt" in alert[0] for alert in alerts)


def test_root_login_detection():
    logs = [
        "2025 Jun 11 11:05:06 server sshd[11116]: Accepted password for root from 203.0.113.2 port 60000 ssh2"
    ]
    alerts = detect_suspicious_entries(logs)
    assert any("Root login detected" in alert[0] for alert in alerts)


def test_true_brute_force_detection():
    logs = [
        "2025 Jun 11 11:00:01 server sshd[11111]: Failed password for admin from 10.0.0.1 port 54321 ssh2",
        "2025 Jun 11 11:00:20 server sshd[11112]: Failed password for admin from 10.0.0.1 port 54322 ssh2",
        "2025 Jun 11 11:00:40 server sshd[11113]: Failed password for admin from 10.0.0.1 port 54323 ssh2",
        "2025 Jun 11 11:01:00 server sshd[11114]: Failed password for admin from 10.0.0.1 port 54324 ssh2",
        "2025 Jun 11 11:01:20 server sshd[11115]: Failed password for admin from 10.0.0.1 port 54325 ssh2"
    ]
    alerts = detect_suspicious_entries(logs, brute_force_threshold=5, brute_force_window=120)
    brute_force_alerts = [a for a in alerts if "Brute-force pattern detected" in a[0]]
    assert len(brute_force_alerts) >= 1


def test_without_brute_force_detection_because_5th_try_is_after_120_seconds():

    logs = [
        "2025 Jun 11 11:00:01 server sshd[11111]: Failed password for admin from 10.0.0.1 port 54321 ssh2",
        "2025 Jun 11 11:00:20 server sshd[11112]: Failed password for admin from 10.0.0.1 port 54322 ssh2",
        "2025 Jun 11 11:00:40 server sshd[11113]: Failed password for admin from 10.0.0.1 port 54323 ssh2",
        "2025 Jun 11 11:01:00 server sshd[11114]: Failed password for admin from 10.0.0.1 port 54324 ssh2",
        "2025 Jun 11 11:01:80 server sshd[11115]: Failed password for admin from 10.0.0.1 port 54325 ssh2"
    ]
    alerts = detect_suspicious_entries(logs)
    brute_force_alerts = [a for a in alerts if "Brute-force pattern detected" in a[0]]
    assert len(brute_force_alerts) == 0
