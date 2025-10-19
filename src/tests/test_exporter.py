import os
import json
import socket
import logging
import pytest
from pathlib import Path
from src.exporter import (
    export_to_csv,
    export_to_json,
    format_rfc5424_message,
    validate_rfc5424_message,
    extract_severity_from_message,
    send_syslog_alert,
)

@pytest.fixture
def sample_alert():
    return {
        "timestamp": "2025-10-18 22:00:00",
        "source": "192.168.1.10",
        "alert": "Failed password for user admin from 192.168.1.10 port 51111 ssh2",
        "pid": 1234,
    }

@pytest.fixture
def sample_alerts():
    return [
        {"timestamp": "2025-10-18 22:00:00", "source": "192.168.1.10", "alert": "Failed login attempt"},
        {"timestamp": "2025-10-18 22:01:00", "source": "10.0.0.1", "alert": "Brute-force detected"},
    ]

def test_export_to_csv_creates_file(tmp_path, sample_alerts):
    csv_path = tmp_path / "alerts.csv"
    export_to_csv(sample_alerts, str(csv_path))

    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "timestamp" in content
    assert "Failed login attempt" in content

def test_export_to_csv_empty_list(tmp_path):
    csv_path = tmp_path / "alerts.csv"
    export_to_csv([], str(csv_path))
    assert not csv_path.exists()

def test_export_to_json_creates_file(tmp_path, sample_alerts):
    json_path = tmp_path / "alerts.json"
    export_to_json(sample_alerts, str(json_path))

    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["alert"] == "Failed login attempt"

def test_export_to_json_invalid_data(tmp_path):
    json_path = tmp_path / "alerts.json"
    invalid_data = [{"alert": lambda x: x}]
    export_to_json(invalid_data, str(json_path))
    assert not json_path.exists()

def test_format_rfc5424_message_valid(sample_alert):
    message = format_rfc5424_message(sample_alert)
    assert message.startswith("<134>1")
    assert "LogAnalyzer" in message
    assert "[event@32473" in message

def test_format_rfc5424_message_missing_fields():
    alert = {}
    msg = format_rfc5424_message(alert)
    assert "<134>1" in msg
    assert "Unknown event" in msg

def test_validate_rfc5424_message_valid(sample_alert):
    message = format_rfc5424_message(sample_alert)
    assert validate_rfc5424_message(message) is True

def test_validate_rfc5424_message_invalid_structure():
    msg = "<134>Not an RFC message"
    assert validate_rfc5424_message(msg) is False

def test_validate_rfc5424_message_invalid():
    invalid_message = "Not a syslog message"
    assert validate_rfc5424_message(invalid_message) is False

def test_extract_severity_from_message_valid():
    message = "<134>1 2025-10-18T00:00:00Z host app 1234 ALERT [data] something happened"
    assert extract_severity_from_message(message) == 6  # 134 % 8 = 6

def test_extract_severity_from_message_invalid():
    message = "Missing angle brackets"
    assert extract_severity_from_message(message) == 6

def test_extract_severity_from_message_invalid_values():
    msgs = [
        "No angle brackets",
        "<abc> invalid numeric",
        "<9999> missing closing bracket",
        "",
        None,
    ]
    for msg in msgs:
        assert extract_severity_from_message(msg) == 6


@pytest.fixture
def udp_server():
    # Simple UDP mock server to receive syslog messages.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 5514))
    sock.settimeout(2.0)
    yield sock
    sock.close()


def test_send_syslog_alert_udp_success(sample_alert, udp_server):
    send_syslog_alert(sample_alert, server="127.0.0.1", port=5514, use_tcp=False)
    try:
        data, _ = udp_server.recvfrom(8192)
        decoded = data.decode(errors="ignore")
        assert "<134>" in decoded
        assert "Failed password" in decoded
    except socket.timeout:
        pytest.fail("No syslog message received via UDP")


def test_send_syslog_alert_invalid_host(sample_alert):
    try:
        send_syslog_alert(sample_alert, server="256.256.256.256", port=514)
    except Exception:
        pytest.fail("send_syslog_alert() should handle invalid host gracefully")


def test_send_syslog_alert_invalid_message(monkeypatch, sample_alert):
    """Simulate invalid RFC message to trigger validation failure"""
    monkeypatch.setattr("exporter.validate_rfc5424_message", lambda _: False)

    result = send_syslog_alert(sample_alert, server="127.0.0.1", port=5514)
    assert result is None  # function should exit silently without raising error