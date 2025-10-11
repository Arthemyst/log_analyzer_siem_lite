import typer

from logs_anaylyzer import LogsAnalyzer

app = typer.Typer()
paths_to_files = ["./test.log"]

@app.command()
def analyze_logs(path_to_file: str = None, realtime: bool = False) -> None:
    if realtime:
        LogsAnalyzer.start_realtime_monitoring(paths_to_files)
    elif path_to_file:
        alerts = LogsAnalyzer.analyze_logs_file(path_to_file)
        LogsAnalyzer.generate_pdf_report(alerts)
    else:
        typer.echo("Please specify --file or --realtime")


if __name__ == "__main__":
    app()
