import typer

app = typer.Typer()


class LogsAnalyzer:
    @staticmethod
    def analyze_logs(log_file):
        with open(log_file) as f:
            for line in f:
                if 'Failed password' in line:
                    print('[!] Brute-force detected:', line.strip())


@app.command()
def analyze_logs(path_to_file: str):
    LogsAnalyzer.analyze_logs(path_to_file)


# '/var/log/auth.log'
if __name__ == "__main__":
    app()
