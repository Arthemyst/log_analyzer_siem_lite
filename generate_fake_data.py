import json
import os
import random
import time
import uuid
from datetime import datetime
import requests

HONEYPOT_URL = "http://localhost:8080"
HONEYPOT_EVENTS_FILE = "logs/honeypot_events.jsonl"
SYSLOG_FILE = "logs/received_syslog.log"
SIEM_ALERTS_FILE = "alerts/alerts.json"

ATTACK_PATHS = [
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/admin/login",
    "/login?user=root",
    "/index.php",
    "/cgi-bin/test.cgi",
    "/shell",
    "/cmd",
    "/etc/passwd",
]

USER_AGENTS = [
    "Mozilla/5.0",
    "curl/7.88",
    "python-requests/2.31",
    "sqlmap/1.6",
    "Nmap Scripting Engine",
]

PAYLOADS = [
    "id=1 UNION SELECT password FROM users",
    "<script>alert(1)</script>",
    "GET /etc/passwd HTTP/1.1",
    "username=admin&password=admin123",
    "",
    "cat /etc/shadow",
]

SIEM_ALERT_TYPES = [
    "Brute-force attack detected",
    "Multiple failed SSH logins",
    "Suspicious IP activity",
    "Threat Intelligence: Malicious IP detected",
]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_honeypot_event():
    path = random.choice(ATTACK_PATHS)
    payload = random.choice(PAYLOADS)
    user_agent = random.choice(USER_AGENTS)

    try:
        url = HONEYPOT_URL + path
        print(f"[HONEYPOT] -> {url}")

        res = requests.post(
            url,
            data=payload,
            headers={"User-Agent": user_agent},
            timeout=3
        )

        print("[OK] Honeypot status:", res.status_code)
        return {"url": url, "status": res.status_code, "payload": payload}

    except Exception as e:
        print("[ERROR] Honeypot request failed:", e)
        return None


def generate_syslog_event():
    pri = random.randint(0, 191)
    version = 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%SZ")
    hostname = f"host-{random.randint(1, 50)}"
    appname = "FakeSyslogGen"
    procid = str(random.randint(1000, 9999))
    msgid = f"ID{random.randint(100,999)}"

    structured_data = f'[example@12345 event="simulated" uuid="{uuid.uuid4()}"]'
    message = f"Simulated syslog event number {random.randint(1, 9999)}"

    rfc5424_msg = (
        f"<{pri}>{version} {timestamp} {hostname} {appname} {procid} "
        f"{msgid} {structured_data} {message}"
    )

    line = f"{timestamp} | UDP | {rfc5424_msg}"

    os.makedirs(os.path.dirname(SYSLOG_FILE), exist_ok=True)
    with open(SYSLOG_FILE, "a") as f:
        f.write(line + "\n")

    return line


def generate_siem_event():
    alerts = []
    os.makedirs(os.path.dirname(SIEM_ALERTS_FILE), exist_ok=True)
    if os.path.exists(SIEM_ALERTS_FILE):
        try:
            alerts = json.load(open(SIEM_ALERTS_FILE))
        except:
            alerts = []

    event = {
        "timestamp": datetime.now().isoformat() + "Z",
        "source": random_ip(),
        "alert": random.choice(SIEM_ALERT_TYPES),
        "severity": random.choice(["low", "medium", "high"]),
    }
    alerts.append(event)

    os.makedirs(os.path.dirname(SIEM_ALERTS_FILE), exist_ok=True)
    json.dump(alerts[-200:], open(SIEM_ALERTS_FILE, "w"), indent=4)

    return event


def generate_burst(count=20, delay=0.1):
    print(f"Generating {count} attack events...")

    for _ in range(count):
        generate_honeypot_event()
        generate_syslog_event()
        generate_siem_event()
        time.sleep(delay)

    print("Burst complete.")


if __name__ == "__main__":
    print("=== Fake Data Generator ===")
    print("1. Generate 1 honeypot event")
    print("2. Generate 1 syslog event")
    print("3. Generate 1 SIEM-lite alert")
    print("4. Generate a burst attack (20 events)")
    print("5. Exit")

    while True:
        choice = input("\nChoose option: ").strip()

        if choice == "1":
            print(generate_honeypot_event())
        elif choice == "2":
            print(generate_syslog_event())
        elif choice == "3":
            print(generate_siem_event())
        elif choice == "4":
            generate_burst()
        elif choice == "5":
            break
        else:
            print("Invalid option.")
