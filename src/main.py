import typer
from logs_analyzer import LogsAnalyzer

from exporter import export_to_csv, export_to_json, send_syslog_alert

app = typer.Typer(help="SIEM-lite Log Analyzer")
DEFAULT_PATHS = ["./test.log"]


@app.command()
def analyze_logs(
        file: str = typer.Option(None, "--file", "-f", help="Path to log file to analyze."),
        realtime: bool = typer.Option(False, "--realtime", "-r", help="Enable real-time monitoring mode."),
        export_csv: bool = typer.Option(False, "--csv", help="Export alerts to CSV."),
        export_json: bool = typer.Option(False, "--json", help="Export alerts to JSON."),
        syslog: bool = typer.Option(False, "--syslog", help="Forward alerts to Syslog server."),
        generate_report: bool = typer.Option(False, "--report", "-p", help="Generate PDF report after analysis.")
) -> None:
    if realtime:
        typer.echo("[INFO] Starting real-time log monitoring...")
        LogsAnalyzer.start_realtime_monitoring(DEFAULT_PATHS)
        return

    if not file:
        typer.echo("[ERROR] Please specify a log file with --file or use --realtime for live monitoring.")
        raise typer.Exit()

    typer.echo(f"[INFO] Analyzing file: {file}")
    alerts = LogsAnalyzer.analyze_logs_file(file)

    if not alerts:
        typer.echo("[INFO] No suspicious activity detected.")
        return

    typer.echo(f"[INFO] Detected {len(alerts)} suspicious entries.")

    if generate_report:
        typer.echo("[INFO] Generating PDF report...")
        LogsAnalyzer.generate_pdf_report(alerts)

    if export_csv:
        typer.echo("[INFO] Exporting alerts to CSV...")
        export_to_csv(alerts)
    if export_json:
        typer.echo("[INFO] Exporting alerts to JSON...")
        export_to_json(alerts)
    if syslog:
        typer.echo("[INFO] Sending alerts to Syslog server...")
        for alert in alerts:
            send_syslog_alert({
                "source": file,
                "alert": alert[0],
                "log": alert[1]
            })

    typer.echo("[INFO] Analysis completed successfully.")


if __name__ == "__main__":
    app()
