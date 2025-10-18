import csv
import json
import logging
import socket
from datetime import datetime
from logging.handlers import SysLogHandler, RotatingFileHandler
from pathlib import Path
from typing import Optional, List
import requests
import os

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "exporter.log"

logger = logging.getLogger("Exporter")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_format = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
console_handler.setFormatter(console_format)

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(console_format)

if not logger.hasHandlers():
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

EXPORT_DIR = Path("exports")
EXPORT_DIR.mkdir(exist_ok=True)

def export_alerts_to_csv(alerts: List[dict], filename: Optional[str] = None) -> Optional[Path]:
    if not alerts:
        logger.warning("[CSV] No alerts to export")
        return None

    if not filename:
        filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    filepath = EXPORT_DIR / filename
    fieldnames = list({k for a in alerts for k in a.keys()})

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                writer.writerow(alert)
        logger.info(f"[CSV] Exported {len(alerts)} alerts -> {filepath}")
        return filepath

    except (OSError, IOError) as e:
        logger.error(f"[CSV] File write error: {e}")
        return None


def export_alerts_to_json(alerts: List[dict], filename: Optional[str] = None) -> Optional[Path]:
    if not alerts:
        logger.warning("[JSON] No alerts to export")
        return None

    if not filename:
        filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    filepath = EXPORT_DIR / filename

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=4, ensure_ascii=False)
        logger.info(f"[JSON] Exported {len(alerts)} alerts -> {filepath}")
        return filepath

    except (OSError, IOError, TypeError) as e:
        logger.error(f"[JSON] Export failed: {e}")
        return None


def format_rfc5424_message(alert: dict, hostname: str = None, app_name: str = "LogAnalyzer") -> str:
    priority = 134
    version = 1
    timestamp = alert.get("timestamp", datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    hostname = hostname or socket.gethostname()
    pid = os.getpid()
    event_id = alert.get("event_id", "ID" + datetime.now().strftime("%H%M%S"))

    user = alert.get("username", "unknown")
    src_ip = alert.get("ip", "unknown")
    event_type = alert.get("alert_type", "N/A")
    score = alert.get("threat_intel", {}).get("abuse_Score", "N/A")

    structured_data = f'[event@32473 user="{user}" src_ip="{src_ip}" type="{event_type}" score="{score}"]'
    message_body = alert.get("description", alert.get("log", "No details provided"))

    return f"<{priority}>{version} {timestamp} {hostname} {app_name} {pid} {event_id} {structured_data} {message_body}"


def send_syslog_alert(alert: dict, server: str = "127.0.0.1", port: int = 514, use_tcp: bool = False, app_name: str = "LogAnalyzer") -> None:
    try:
        socket_type = socket.SOCK_STREAM if use_tcp else socket.SOCK_DGRAM
        handler = SysLogHandler(address=(server, port), socktype=socket_type)
        sys_logger = logging.getLogger("RFC5424Forwarder")
        sys_logger.setLevel(logging.INFO)
        sys_logger.addHandler(handler)

        message = format_rfc5424_message(alert, app_name=app_name)
        sys_logger.info(message)

        handler.close()
        sys_logger.removeHandler(handler)
        logger.info(f"[SYSLOG] RFC 5424 alert sent -> {server}:{port} ({'TCP' if use_tcp else 'UDP'})")

    except ConnectionRefusedError:
        logger.error(f"[SYSLOG] Connection refused: {server}:{port}")
    except TimeoutError:
        logger.error(f"[SYSLOG] Connection timed out: {server}:{port}")
    except OSError as e:
        logger.error(f"[SYSLOG] OS-level error: {e}")
    except Exception as e:
        logger.exception(f"[SYSLOG] Unexpected error while sending Syslog: {e}")

def send_alert_to_siem_api(
        alert: dict,
        siem_url: str,
        token: Optional[str] = None,
        timeout: int = 5
):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.post(siem_url, headers=headers, json=alert, timeout=timeout)
        response.raise_for_status()
        logger.info(f"[SIEM-API] Sent alert -> {siem_url} ({response.status_code})")

    except requests.exceptions.Timeout:
        logger.error("[SIEM-API] Request timed out.")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[SIEM-API] Connection error: {e}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"[SIEM-API] HTTP error: {e.response.status_code} {e.response.text[:200]}")
    except requests.RequestException as e:
        logger.error(f"[SIEM-API] Request failed: {e}")


def export_all(
        alerts: List[dict],
        export_csv: bool = True,
        export_json: bool = True,
        export_syslog: bool = False,
        export_siem_api: bool = False,
        siem_server: str = "127.0.0.1",
        siem_port: int = 514,
        siem_url: Optional[str] = None,
        siem_token: Optional[str] = None,
        use_tcp_syslog: bool = False
):
    if not alerts:
        logger.warning("[EXPORT] No alerts to export]")
        return

    logger.info(f"[EXPORT] Starting export of {len(alerts)} alerts...")

    if export_csv:
        export_alerts_to_csv(alerts)

    if export_json:
        export_alerts_to_json(alerts)

    if export_syslog:
        for alert in alerts:
            send_syslog_alert(alert, siem_server, siem_port, use_tcp_syslog)

    if export_siem_api:
        if not siem_url:
            logger.warning("[EXPORT] API export requested but no siem_url provided.")
        else:
            for alert in alerts:
                send_alert_to_siem_api(alert, siem_url, siem_token)

    logger.info("[EXPORT] All exports completed successfully.")
