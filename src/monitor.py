import asyncio
import json
import os
from datetime import datetime
from typing import Optional
import re
import aiofiles

from suspicious_patterns import detect_suspicious_entries
from threat_intel import fetch_ip_info, severity_from_score

ALERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alerts")
ALERT_JSON = os.path.join(ALERTS_DIR, "alerts.json")


async def monitor_logs(paths):
    tasks = [asyncio.create_task(follow_file(path)) for path in paths]
    await asyncio.gather(*tasks)


async def follow_file(path: str):
    print(f"- Following {path}")

    while not os.path.exists(path):
        print(f"- Waiting for {path}")
        await asyncio.sleep(2)

    async with aiofiles.open(path, 'r') as file:
        await file.seek(0, os.SEEK_END)
        while True:
            line = await file.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            line = line.strip()
            if line:
                await process_line(line, path)


async def process_line(line: str, source: str):
    try:
        result = detect_suspicious_entries([line])
        if not result:
            return

        timestamp = datetime.now().isoformat()

        ip_match = re.search(r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        intel_data = None
        if ip_match:
            ip = ip_match.group(1)
            intel_data = await fetch_ip_info(ip)
            if intel_data:
                print(
                    f"[THREAT INTEL] {ip} | score={intel_data['abuse_score']} "
                    f"severity={intel_data['severity']} | country={intel_data['country']} | ISP={intel_data['isp']}"
                )

        alert = {
            "timestamp": timestamp,
            "source": source,
            "log": line,
            "alerts": [{"type": a[0], "message": a[1]} for a in result],
            "threat_intel": intel_data
        }

        await save_alert(alert)
        print(f"[ALERT] {timestamp} | {source} -> {result}")

    except Exception as e:
        print(f"[ERROR] Processing line: {e}")


async def save_alert(alert: dict):
    try:
        os.makedirs(ALERTS_DIR, exist_ok=True)
        alerts = []
        if os.path.exists(ALERT_JSON):
            async with aiofiles.open(ALERT_JSON, 'r') as f:
                content = await f.read()
                if content:
                    try:
                        alerts = json.loads(content)
                    except json.decoder.JSONDecodeError:
                        alerts = []

        alerts.append(alert)

        async with aiofiles.open(ALERT_JSON, 'w') as f:
            await f.write(json.dumps(alerts, indent=4))

    except Exception as e:
        print(f"[ERROR] Saving alert: {e}")


def start_monitor(paths: Optional[list[str]] = None) -> None:
    print(f"- Starting asynchronous monitoring for: {paths}")
    try:
        asyncio.run(monitor_logs(paths))
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
