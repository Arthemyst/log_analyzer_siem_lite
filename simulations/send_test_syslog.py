from src.exporter import send_syslog_alert
import random

IPS = ["203.0.113.5", "198.51.100.44", "192.0.2.55"]

EVENTS = [
    "Honeypot: wordpress scan",
    "SSH brute-force attempt",
    "Unauthorized SQL injection test",
    "XSS probe detected",
]

for _ in range(10):
    alert = {
        "source": random.choice(IPS),
        "alert": random.choice(EVENTS),
        "pid": random.randint(1000, 9999),
    }
    print("[+] Sending alert:", alert)
    send_syslog_alert(alert, server="127.0.0.1", port=514)
