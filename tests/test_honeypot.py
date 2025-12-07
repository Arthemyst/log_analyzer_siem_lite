import json
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from honeypot import honeypot
from honeypot.honeypot import app, classify_attack, save_event_locally


def test_classify_attack_wordpress():
    assert classify_attack("/wp-admin/login", "-", "-") == "wordpress-scan"


def test_classify_attack_phpmyadmin():
    assert classify_attack("/phpmyadmin/setup", "-", "-") == "PHPMyAdmin scan"


def test_classify_attack_cmd_probe():
    assert classify_attack("/shell/exec", "-", "-") == "Command execution probe"


def test_classify_attack_file_disclosure():
    assert classify_attack("/etc/passwd", "-", "-") == "File disclosure probe"
    assert classify_attack("/", "aaa PASSWD bbb", "-") == "File disclosure probe"


def test_classify_attack_xss():
    assert classify_attack("/", "<script>alert(1)</script>", "-") == "XSS attack"


def test_classify_attack_sql():
    assert classify_attack("/", "UNION SELECT * FROM users", "-") == "SQL injection"


def test_classify_attack_credential_stuff():
    assert classify_attack("/login", "password=123", "-") == "Credential stuffing attempt"


def test_classify_attack_automated_user_agent():
    assert classify_attack("/", "x", "python-requests") == "automated-scan"


def test_classify_attack_generic():
    assert classify_attack("/random/path", "", "Mozilla") == "generic-attack"


def test_save_event_locally(tmp_path, monkeypatch):
    test_file = tmp_path / "events.jsonl"

    monkeypatch.setattr(honeypot, "HONEYPOT_EVENTS_FILE", str(test_file))

    event = {"test": True}
    save_event_locally(event)

    assert test_file.exists()
    saved = json.loads(test_file.read_text().strip())
    assert saved == event


def test_save_event_locally_permission_error(monkeypatch):
    def mock_open(*args, **kwargs):
        raise PermissionError("No permission")

    monkeypatch.setattr("builtins.open", mock_open)

    # Should not raise
    save_event_locally({"x": 1})


@pytest.mark.asyncio
async def test_honeypot_basic_request(tmp_path, monkeypatch):
    events_file = tmp_path / "honeypot_events.jsonl"

    monkeypatch.setattr(honeypot, "HONEYPOT_EVENTS_FILE", str(events_file))

    mock_syslog = MagicMock()
    monkeypatch.setattr(honeypot, "send_syslog_alert", mock_syslog)

    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/abc/def")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"

    assert events_file.exists()
    event = json.loads(events_file.read_text().splitlines()[0])

    assert event["route"] == "/abc/def"
    assert event["attack_type"] in ["generic-attack", "automated-scan"]
    mock_syslog.assert_called_once()


@pytest.mark.asyncio
async def test_honeypot_post_sql_injection(tmp_path, monkeypatch):
    events_file = tmp_path / "honeypot_events.jsonl"
    monkeypatch.setattr(honeypot, "HONEYPOT_EVENTS_FILE", str(events_file))

    mock_syslog = MagicMock()
    monkeypatch.setattr(honeypot, "send_syslog_alert", mock_syslog)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.post("/login", content="UNION SELECT * FROM users")

    assert response.status_code == 200

    event = json.loads(events_file.read_text().splitlines()[0])
    assert event["attack_type"] == "SQL injection"
    assert "UNION" in event["payload"]
    mock_syslog.assert_called_once()


@pytest.mark.asyncio
async def test_honeypot_binary_payload(tmp_path, monkeypatch):
    events_file = tmp_path / "honeypot_events.jsonl"
    monkeypatch.setattr(honeypot, "HONEYPOT_EVENTS_FILE", str(events_file))

    mock_syslog = MagicMock()
    monkeypatch.setattr(honeypot, "send_syslog_alert", mock_syslog)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.post("/upload", content=b"\xFF\x00\xAA\x11")

    assert response.status_code == 200

    event = json.loads(events_file.read_text().splitlines()[0])
    assert event["payload"] in ("<binary payload>", "-")
    mock_syslog.assert_called_once()


@pytest.mark.asyncio
async def test_honeypot_syslog_exception(tmp_path, monkeypatch):
    events_file = tmp_path / "honeypot_events.jsonl"
    monkeypatch.setattr(honeypot, "HONEYPOT_EVENTS_FILE", str(events_file))

    def mock_error(*args, **kwargs):
        raise OSError("Test syslog failure")

    monkeypatch.setattr(honeypot, "send_syslog_alert", mock_error)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.get("/xyz")

    assert resp.status_code == 200
    assert events_file.exists()  # event must still be saved locally
