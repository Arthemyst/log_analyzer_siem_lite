import typer

from suspicious_patterns import detect_suspicious_entries
from generate_report import generate_pdf_report
from utils import load_log_file

app = typer.Typer()


class LogsAnalyzer:
    @staticmethod
    def analyze_logs(log_file: str) -> list:
        lines = load_log_file(log_file)
        return detect_suspicious_entries(lines)

    @staticmethod
    def generate_pdf_report(alerts: list) -> None:
        generate_pdf_report(alerts)


@app.command()
def analyze_logs(path_to_file: str) -> None:
    alerts = LogsAnalyzer.analyze_logs(path_to_file)
    LogsAnalyzer.generate_pdf_report(alerts)


# '/var/log/auth.log'
if __name__ == "__main__":
    app()
