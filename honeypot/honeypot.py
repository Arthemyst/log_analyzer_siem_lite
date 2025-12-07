import json
import logging
import os
from datetime import datetime

from fastapi import FastAPI, Request

from src.exporter import send_syslog_alert

app = FastAPI()

logger = logging.getLogger('Honeypot')
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('honeypot.log')
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

HONEYPOT_EVENTS_FILE = "honeypot_events.jsonl"


def save_event_locally(event: dict):
    try:
        with open(HONEYPOT_EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except FileNotFoundError as e:
        logger.error(f"[HONEYPOT] Directory missing for local event file: {e}")
    except PermissionError as e:
        logger.error(f"[HONEYPOT] Permission denied writing event file: {e}")
    except OSError as e:
        logger.error(f"[HONEYPOT] OS error while saving event: {e}")
    except Exception as e:
        logger.exception(f"[HONEYPOT] Unexpected error while saving event: {e}")


def classify_attack(path: str, payload: str, user_agent: str) -> str:
    try:
        path = path.lower()
        payload = (payload or "").lower()
        user_agent = (user_agent or "").lower()

        if "wp-admin" in path or "xmlrpc" in path:
            return "wordpress-scan"

        if path.startswith("/phpmyadmin"):
            return "PHPMyAdmin scan"

        if "shell" in path or "cmd" in path:
            return "Command execution probe"

        if "etc/passwd" in path or "passwd" in payload:
            return "File disclosure probe"

        if "<script>" in payload:
            return "XSS attack"

        if "select" in path or "union" in path:
            return "SQL injection"

        if "login" in path and "password" in payload:
            return "Credential stuffing attempt"

        if "python" in user_agent or "curl" in user_agent:
            return "automated-scan"

        return "generic-attack"

    except Exception as e:
        logger.error(f"[HONEYPOT] Attack classification failed: {e}")
        return "unknown"


@app.api_route("/{full_path:path}", methods=["GET", "POST"])
async def catch_all(request: Request, full_path: str):
    attacker_ip = request.client.host
    user_agent = request.headers.get("User-Agent", "-")

    try:
        raw_body = await request.body()
        payload = raw_body.decode("utf-8") if raw_body else "-"
    except UnicodeDecodeError:
        payload = "<binary payload>"
    except Exception as e:
        logger.error(f"[HONEYPOT] Failed to read request body: {e}")
        payload = "-"

    attack_type = classify_attack(full_path, payload, user_agent)

    event = {
        "timestamp": datetime.now().isoformat() + "Z",
        "source": attacker_ip,
        "route": f"/{full_path}",
        "payload": payload,
        "attack_type": attack_type,
        "user_agent": user_agent,
    }

    save_event_locally(event)
    logger.warning(f"[HONEYPOT] Event: {event}")

    syslog_alert = {
        "source": attacker_ip,
        "alert": f"[HONEYPOT] {attack_type} @ /{full_path} | UA={user_agent} | payload={payload[:80]}",
        "pid": 0,
    }

    try:
        send_syslog_alert(syslog_alert)
    except ConnectionRefusedError:
        logger.error("[HONEYPOT] Syslog server refused connection")
    except TimeoutError:
        logger.error("[HONEYPOT] Syslog server timeout")
    except OSError as e:
        logger.error(f"[HONEYPOT] Syslog OS-level error: {e}")
    except Exception as e:
        logger.exception(f"[HONEYPOT] Unexpected Syslog error: {e}")

    return {"status": "OK", "message": "Welcome"}


if __name__ == "__main__":
    import uvicorn

    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger("[START] FastAPI Honeypot running on 0.0.0.0.8080")
    uvicorn.run("honeypot:app", host="0.0.0.0", port=8080, reload=False)
