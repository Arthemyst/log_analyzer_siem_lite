import typer

from logs_anaylyzer import LogsAnalyzer

app = typer.Typer()


@app.command()
def analyze_logs(path_to_file: str) -> None:
    alerts = LogsAnalyzer.analyze_logs(path_to_file)
    LogsAnalyzer.generate_pdf_report(alerts)


if __name__ == "__main__":
    app()
