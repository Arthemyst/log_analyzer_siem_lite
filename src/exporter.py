import csv
import json
import logging
import os
import re
import socket
import tempfile
from datetime import datetime
from logging.handlers import SysLogHandler

logger = logging.getLogger("Exporter")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("exporter.log")
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def export_to_csv(alerts: list[dict], path: str = "exports/alerts.csv") -> None:
    if not alerts:
        logger.info("[EXPORT] No alerts to export.")
        return

    try:
        target_dir = os.path.dirname(path) or "."
        os.makedirs(target_dir, exist_ok=True)

        fieldnames = list(alerts[0].keys())

        with tempfile.NamedTemporaryFile("w", delete=False, dir=target_dir, newline="", encoding="utf-8") as tmpf:
            writer = csv.DictWriter(tmpf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(alerts)
            temp_name = tmpf.name

        os.replace(temp_name, path)

        logger.info(f"[EXPORT] Alerts exported to CSV: {path}")

    except (OSError, IOError) as e:
        logger.error(f"[EXPORT] File error during CSV export: {e}")
        if 'temp_name' in locals() and os.path.exists(temp_name):
            os.remove(temp_name)
    except Exception as e:
        logger.error(f"[EXPORT] Unexpected error during CSV export: {type(e).__name__} - {e}")
        if 'temp_name' in locals() and os.path.exists(temp_name):
            os.remove(temp_name)

def export_to_json(alerts: list[dict], path: str = "exports/alerts.json") -> None:
    try:
        if not alerts:
            logger.info("[EXPORT] No alerts to export.")
            return
        try:
            payload = json.dumps(alerts, indent=4, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            logger.error(f"[EXPORT] Failed to export alerts: {e}")
            return

        target_dir = os.path.dirname(path) or "."
        os.makedirs(target_dir, exist_ok=True)

        dir_for_temp = target_dir
        with tempfile.NamedTemporaryFile("w", delete=False, dir=dir_for_temp, encoding="utf-8") as tmpf:
            tmpf.write(payload)
            temp_name = tmpf.name

        os.replace(temp_name, path)

        logger.info(f"[EXPORT] Alerts exported to JSON: {path}")

    except (OSError, IOError) as e:
        logger.error(f"[EXPORT] Unexpected error during JSON export: {type(e).__name__} - {e}")
        if 'temp_name' in locals() and os.path.exists(temp_name):
            os.remove(temp_name)



def format_rfc5424_message(alert: dict, app_name: str = "LogAnalyzer") -> str:
    """
    Format alert dictionary into RFC 5424 Syslog message.
    Example output:
    <134>1 2025-10-18T18:00:00Z host LogAnalyzer 1234 ID99 [event@32473 user="root" src_ip="1.2.3.4"] message
    """
    pri = 134  # facility(16)*8 + severity(6)
    version = 1
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = socket.gethostname()
    procid = str(alert.get("pid", "-"))
    msgid = "ALERT"
    structured_data = f"[event@32473 src_ip=\"{alert.get('source', '-')}\"]"
    message_text = alert.get("alert", "Unknown event")

    formatted_message = f"<{pri}>{version} {timestamp} {hostname} {app_name} {procid} {msgid} {structured_data} {message_text}"
    return formatted_message


def extract_severity_from_message(message: str) -> int:
    default_severity = 6
    if not isinstance(message, str):
        logger.debug("[SYSLOG] Non-string message passed; defaulting severity=6.")
        return default_severity

    if "<" not in message or ">" not in message:
        logger.debug("[SYSLOG] Message missing PRI field; defaulting severity=6.")
        return default_severity

    try:
        start = message.find("<")
        end = message.find(">", start + 1)
        if start == -1 or end == -1 or end <= start + 1:
            logger.debug("[SYSLOG] Invalid PRI delimiters; defaulting severity=6.")
            return default_severity

        pri_part = message[start + 1:end].strip()
        if not pri_part.isdigit():
            logger.debug(f"[SYSLOG] Non-numeric PRI value '{pri_part}'; defaulting severity=6.")
            return default_severity

        pri_val = int(pri_part)
        # RFC 5424 valid PRI range is 0–191
        if not (0 <= pri_val <= 191):
            logger.debug(f"[SYSLOG] Out-of-range PRI value '{pri_val}'; defaulting severity=6.")
            return default_severity

        return pri_val % 8
    except (ValueError, IndexError, TypeError) as e:
        logger.debug(f"[SYSLOG] PRI parsing failed ({type(e).__name__}): {e}. Defaulting severity=6.")
        return default_severity


def validate_rfc5424_message(message: str) -> bool:
    if not isinstance(message, str):
        logger.debug("[SYSLOG] Non-string message passed to validation.")
        return False

    rfc5424_pattern = re.compile(
        r"^<\d{1,3}>\d\s"
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s"
        r"[A-Za-z0-9\-\._]+\s"
        r"[A-Za-z0-9\-\._]+\s"
        r"[\d\-]+\s"
        r"[A-Za-z0-9\-]+\s"
        r"\[[^\]]*\].*"
    )

    if not rfc5424_pattern.match(message):
        logger.debug(f"[SYSLOG] RFC 5424 validation failed: {message[:80]}...")
        return False

    timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", message)
    if not timestamp_match:
        logger.debug("[SYSLOG] Invalid or missing timestamp in message.")
        return False

    try:
        datetime.strptime(timestamp_match.group(0), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        logger.debug("[SYSLOG] Invalid or missing timestamp in message.")
        return False

    if "[" not in message or "]" not in message:
        logger.debug("[SYSLOG] Missing structured data block [].")
        return False

    logger.debug("[SYSLOG] RFC 5424 validation passed.")
    return True


def send_syslog_alert(alert: dict, server: str = "127.0.0.1", port: int = 514, use_tcp: bool = False) -> None:
    try:
        message = format_rfc5424_message(alert)
        if not validate_rfc5424_message(message):
            logger.warning("[SYSLOG] Message skipped — failed RFC 5424 validation.")
            return

        socktype = socket.SOCK_STREAM if use_tcp else socket.SOCK_DGRAM
        handler = SysLogHandler(address=(server, port), socktype=socktype)
        sys_logger = logging.getLogger("SyslogForwarder")
        sys_logger.addHandler(handler)
        sys_logger.setLevel(logging.INFO)
        sys_logger.info(message)
        handler.close()
        sys_logger.removeHandler(handler)
        logger.info(f"[SYSLOG] Sent alert -> {server}:{port} ({'TCP' if use_tcp else 'UDP'})")

    except ConnectionRefusedError:
        logger.error(f"[SYSLOG] Connection refused: {server}:{port}")
    except TimeoutError:
        logger.error(f"[SYSLOG] Connection timed out: {server}:{port}")
    except OSError as e:
        logger.error(f"[SYSLOG] OS-level error: {e}")
    except Exception as e:
        logger.error(f"[SYSLOG] Unexpected error: {type(e).__name__}: {e}")
