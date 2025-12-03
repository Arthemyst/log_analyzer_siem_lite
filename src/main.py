import asyncio
import os

import typer

from src.exporter import export_to_csv, export_to_json, send_syslog_alert
from src.logs_analyzer import LogsAnalyzer
import src.syslog_receiver as syslog_receiver
from src.syslog_pipeline import SyslogPipeline

app = typer.Typer(help="SIEM-lite Log Analyzer")
DEFAULT_PATHS = ["./test.log"]


@app.command("analyze")
def analyze_logs(
        file: str = typer.Option(None, "--file", "-f", help="Path to log file to analyze."),
        export_csv: bool = typer.Option(False, "--csv", help="Export alerts to CSV."),
        export_json: bool = typer.Option(False, "--json", help="Export alerts to JSON."),
        syslog: bool = typer.Option(False, "--syslog", help="Forward alerts to Syslog server."),
        generate_report: bool = typer.Option(False, "--report", "-p", help="Generate PDF report."),
        report_path: str = typer.Option("report.pdf", "--report-path", "-rp",
                                        help="Path to save PDF report.")
) -> None:
    if not file:
        typer.echo("[ERROR] Use --file <path> to analyze a log file.")
        raise typer.Exit()

    typer.echo(f"[INFO] Analyzing file: {file}")
    alerts = LogsAnalyzer.analyze_logs_file(file)

    if not alerts:
        typer.echo("[INFO] No suspicious activity detected.")
        return

    typer.echo(f"[INFO] Detected {len(alerts)} suspicious entries.")

    if generate_report:
        typer.echo("[INFO] Generating PDF report...")
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        LogsAnalyzer.generate_pdf_report(alerts)
        typer.echo(f"[INFO] Report saved: {report_path}")

    if export_csv:
        typer.echo("[INFO] Exporting alerts to CSV...")
        export_to_csv(alerts)

    if export_json:
        typer.echo("[INFO] Exporting alerts to JSON...")
        export_to_json(alerts)

    if syslog:
        typer.echo("[INFO] Sending alerts to Syslog server...")
        for name, log_line in alerts:
            send_syslog_alert({
                "source": file,
                "alert": name,
                "log": log_line,
            })

    typer.echo("[INFO] Analysis completed successfully.")


@app.command("realtime")
def realtime_monitor(
        paths: str = typer.Option(None, "--paths", "-p",
                                  help="Comma-separated list of files to monitor (tail -f style).")
):
    path_list = [p.strip() for p in paths.split(",")] if paths else DEFAULT_PATHS

    typer.echo(f"[INFO] Starting realtime monitoring for: {path_list}")
    LogsAnalyzer.start_realtime_monitoring(path_list)


@app.command("syslog")
def syslog_receiver_command(
        udp_port: int = typer.Option(514, "--udp-port", help="UDP port for Syslog receiver"),
        tcp_port: int = typer.Option(514, "--tcp-port", help="TCP port for Syslog receiver"),
        host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
):
    typer.echo(f"[INFO] Starting Syslog Receiver on {host} (UDP:{udp_port}, TCP:{tcp_port})")

    analyzer = LogsAnalyzer()
    pipeline = SyslogPipeline(analyzer)
    syslog_receiver.pipeline = pipeline

    try:
        asyncio.run(syslog_receiver.run_syslog_receiver(
            udp_port=udp_port,
            tcp_port=tcp_port,
            host=host,
        ))
    except KeyboardInterrupt:
        typer.echo("[STOP] Syslog Receiver stopped manually.")


if __name__ == "__main__":
    app()
