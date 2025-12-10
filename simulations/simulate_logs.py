import time
import random

LOG_FILE = "samples/simulated_auth.log"

FAILED = [
    "Failed password for root from {ip} port {port} ssh2",
    "Failed password for admin from {ip} port {port} ssh2",
]

SUCCESS = [
    "Accepted password for user from {ip} port {port} ssh2"
]

IPS = ["203.0.113.5", "198.51.100.44", "192.0.2.55"]

def generate():
    ip = random.choice(IPS)
    port = random.randint(30000, 60000)

    if random.random() < 0.8:
        msg = random.choice(FAILED)
    else:
        msg = random.choice(SUCCESS)

    timestamp = time.strftime("%Y %b %d %H:%M:%S")

    line = f"{timestamp} server sshd[11130]: {msg.format(ip=ip, port=port)}"

    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

    print("[+] Log entry added:", line)


if __name__ == "__main__":
    for _ in range(20):
        generate()
        time.sleep(0.3)
