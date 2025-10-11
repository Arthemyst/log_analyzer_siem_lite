import asyncio
import json
import os
from datetime import datetime
from typing import Optional

import aiofiles

from .suspicious_patterns import detect_suspicious_entries

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
        print(f"- Processing {line}")
        result = detect_suspicious_entries([line])
        print(f"- Suspicious entries: {result}")
        if result:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = {
                "timestamp": timestamp,
                "source": source,
                "log": line,
                "alert": result
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
                    alerts = json.loads(content)
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
