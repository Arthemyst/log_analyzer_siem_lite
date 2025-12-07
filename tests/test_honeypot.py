import json
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from honeypot import honeypot
from honeypot.honeypot import app


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
