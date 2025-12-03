from .generate_report import generate_pdf_report
from .monitor import start_monitor
from .suspicious_patterns import detect_suspicious_entries
from .utils import load_log_file

import logging

class LogsAnalyzer:

    def __init__(self):
        self.logger = logging.getLogger("LogsAnalyzer")
        self.detected_alerts = []  # storage for alerts from syslog or realtime


    @staticmethod
    def analyze_logs_file(log_file: str) -> list:
        lines = load_log_file(log_file)
        return detect_suspicious_entries(lines)

    @staticmethod
    def generate_pdf_report(alerts: list) -> None:
        generate_pdf_report(alerts)

    @staticmethod
    def start_realtime_monitoring(paths: list[str]):
        start_monitor(paths)

    def process_syslog_alert(self, alert: dict):
        if not isinstance(alert, dict):
            self.logger.error("[SYSLOG] Invalid alert format; skipping.")
            return None

        self.detected_alerts.append(alert)

        suspicious = detect_suspicious_entries([alert])
        if suspicious:
            alert["suspicious"] = True

        self.logger.info(f"[SYSLOG] Processed alert: {alert}")
        return alert
