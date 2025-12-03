import logging
from datetime import datetime
from .exporter import validate_rfc5424_message
from .logs_analyzer import LogsAnalyzer

logger = logging.getLogger("SyslogPipeline")
logger.setLevel(logging.DEBUG)

def parse_rfc5424_message(message: str) -> dict | None:

    # Example RFC message:
    # <134>1 2025-10-18T18:00:00Z host App 1234 ALERT [event@32473 src_ip="1.2.3.4"] Failed password for root

    try:
        parts = message.split(" ", 7)
        # 0: <PRI>VER
        # 1: timestamp
        # 2: host
        # 3: app
        # 4: pid
        # 5: msgid
        # 6: structured data
        # 7: message text

        timestamp = parts[1]
        source_ip = "-"
        structured_data = parts[6]

        # Extract IP if present: src_ip="X"
        if "src_ip=" in structured_data:
            try:
                source_ip = structured_data.split('src_ip="')[1].split('"')[0]
            except IndexError:
                pass

        msg_text = parts[7] if len(parts) > 7 else "Unknown event"

        return {
            "timestamp": timestamp,
            "source": source_ip,
            "alert": msg_text,
            "pid": parts[4],
            "raw": message
        }

    except Exception as e:
        logger.error(f"[PIPELINE] Failed to parse RFC 5424 message: {e}")
        return None

class SyslogPipeline:

    def __init__(self, analyzer: LogsAnalyzer):
        self.analyzer = analyzer

    def handle_message(self, message: str):
        if not validate_rfc5424_message(message):
            logger.error(f"[PIPELINE] Dropping invalid RFC5424 message")
            return

        alert = parse_rfc5424_message(message)
        if not alert:
            logger.warning(f"[PIPELINE] Failed to parse alert")
            return

        logger.debug(f"[PIPELINE] Parsed alert: {alert}")

        self.analyzer.process_syslog_alert(alert)
