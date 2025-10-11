from .generate_report import generate_pdf_report
from .monitor import start_monitor
from .suspicious_patterns import detect_suspicious_entries
from .utils import load_log_file


class LogsAnalyzer:
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
