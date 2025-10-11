from typing import Optional

import typer

from .logs_anaylyzer import LogsAnalyzer

app = typer.Typer()
paths_to_files = ["./test.log"]


@app.command()
def analyze_logs(
        file: Optional[str] = typer.Option(None, help="Path to log file to analyze (static)"),
        realtime: bool = typer.Option(False, help="Enable realtime monitoring"),
        paths: Optional[str] = typer.Option(None, help="Comma-separated list of paths to monitor in realtime")
) -> None:
    if realtime:
        if paths:
            p = [p.strip() for p in paths.split(",")]
        LogsAnalyzer.start_realtime_monitoring(p)
    elif file:
        alerts = LogsAnalyzer.analyze_logs_file(file)
        LogsAnalyzer.generate_pdf_report(alerts)
    else:
        typer.echo("Specify --file <path> for static analysis OR --realtime [--paths p1,p2]")


if __name__ == "__main__":
    app()
