import typer

from suspicious_patterns import detect_suspicious_entries
from utils import load_log_file

app = typer.Typer()


class LogsAnalyzer:
    @staticmethod
    def analyze_logs(log_file):
        lines = load_log_file(log_file)
        alerts = detect_suspicious_entries(lines)
        for alert_type, log_line in alerts:
            print(f"ALERT: {alert_type}, DETAILS: {log_line}")


@app.command()
def analyze_logs(path_to_file: str):
    LogsAnalyzer.analyze_logs(path_to_file)


# '/var/log/auth.log'
if __name__ == "__main__":
    app()
