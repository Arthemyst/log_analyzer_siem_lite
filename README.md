# 🇵🇱 Log Analyzer (SIEM-lite)

## Opis projektu

**Log Analyzer (SIEM-lite)** to lekki analizator logów systemowych w Pythonie, inspirowany systemami klasy **SIEM (Security Information and Event Management)**.  
Narzędzie wykrywa i klasyfikuje potencjalne incydenty bezpieczeństwa w logach SSH, wzbogacając je o dane z zewnętrznych źródeł **Threat Intelligence**.

Projekt zawiera:
- analizator logów,
- walidator RFC 5424,
- eksport danych (CSV / JSON / Syslog),
- asynchroniczny Syslog Receiver (UDP + TCP),
- pipeline łączący Syslog → Analyzer,
- generowanie raportów PDF.

## Funkcje

- **Monitorowanie logów w czasie rzeczywistym**  
  Asynchroniczny mechanizm śledzenia wpisów (`aiofiles`, `asyncio`).

- **Wykrywanie prób brute-force**  
  Analiza nieudanych logowań w oknach czasowych, wykrywanie ≥ 5 prób logowania w krótkim czasie.  
  Historia przechowywana w SQLite, dzięki czemu dane utrzymują się między restartami.

- **Integracja z Threat Intelligence APIs (AbuseIPDB)**  
  Automatyczne sprawdzanie reputacji adresów IP, zapis danych (kraj, ISP, liczba zgłoszeń, confidence score).  
  Dane są buforowane w lokalnej bazie SQLite, aby ograniczyć zapytania do API.

- **Eksport alertów (exporter module)**  
  Możliwość zapisu alertów do:
  - **CSV**
  - **JSON**
  - **Syslog RFC 5424**
    - formatowanie wiadomości RFC 5424,
    - walidacja strukturalna (bez regex),
    - wysyłanie przez UDP lub TCP
      ```
      send_syslog_alert(alert, server="127.0.0.1", port=514)
      ```
- **Generowanie raportów PDF**  
  Automatyczne tworzenie raportów z incydentami, danymi reputacyjnymi i znacznikami czasu.

- **Trwała baza SQLite**  
  Przechowuje:
  - próby logowania (`failed_logins`)
  - ostatnie alerty brute-force (`alerts_log`)
  - dane reputacyjne IP (`cache`)

## Testy i pokrycie kodu

Projekt zawiera zestaw testów jednostkowych (`pytest`) obejmujący:
- analizy logów i wykrywania incydentów
- eksportera (CSV/JSON/Syslog)
- walidacji RFC 5424
- integracji parsowania

### Uruchamianie testów

```bash
  pytest -v
```

### Sprawdzenie pokrycia testowego

```bash
  pytest --cov=src --cov-report=term-missing
```

Raport pokaże procentowe pokrycie testami oraz pliki, które wymagają dodatkowych testów.

## Struktura projektu

```
src/
 ├── main.py                 # CLI (typer)
 ├── logs_analyzer.py        # Log Analyzer wrapper
 ├── suspicious_patterns.py  # Wykrywanie incydentów SSH
 ├── failed_logins_db.py     # Baza SQLite
 ├── threat_intel.py         # Integracja AbuseIPDB
 ├── exporter.py             # Eksport CSV / JSON / Syslog RFC5424
 ├── syslog_receiver.py      # Asynchroniczny Syslog UDP/TCP receiver
 ├── syslog_pipeline.py      # Pipeline Syslog → Analyzer
 ├── generate_report.py      # Raporty PDF
 └── utils.py                # Pomocnicze funkcje
tests/
 ├── test_exporter.py
 └── test_suspicious_patterns.py
```

## Przykładowy plik logów

- `auth_sample_40.log` — zawiera 20 podejrzanych i 20 prawidłowych wpisów do testowania działania analizera.

## Wymagania
- Python 3.10+

## Instalowanie zależności
```bash 
  pip install -r requirements.txt
```

## Jak uruchomić

### Analiza pojedynczego pliku logów
```bash
  python -m src.main.py --file ./samples/auth_sample_40.log --report
```

- analizuje plik logów,  
- wzbogaca dane o reputację IP,  
- generuje raport `report.pdf`.
- opcjonalnie eksport do CSV/JSON

### Monitorowanie logów w czasie rzeczywistym

```bash
  python -m src.main.py --realtime --paths test.log
```
- obserwuje plik logów w czasie rzeczywistym,  
- zapisuje próby logowania do SQLite (`cache/failed_logins.db`),  
- pobiera reputację IP z AbuseIPDB (cacheowane),  
- zapisuje alerty w `alerts/alerts.json`,  
- opcjonalnie wysyła alerty do serwera Syslog.

## Struktura danych (SQLite)
| Tabela | Opis |
|--------|------|
| `failed_logins` | Historia nieudanych logowań |
| `alerts_log` | Ostatnie alerty brute-force |
| `cache` | Bufor reputacji IP (Threat Intelligence) |

## Syslog Receiver (UDP + TCP)

### Uruchamianie:
```
  python -m src.main syslog --udp-port 514 --tcp-port 514 --host 0.0.0.0
```

### Serwer obsługuje:
- Syslog UDP (RFC 5424)
- Syslog TCP z framingiem (length-prefixed)
- integrację z pipeline

### Pipeline automatycznie przekieruje alerty do:
- LogsAnalyzer
- eksportera
- dalszego przetwarzania (opcjonalnie: Threat Intel, PDF, syslog forward)


## Następne kroki
- **Machine Learning Anomaly Detection** – automatyczne wykrywanie nietypowych wzorców
- **Web Dashboard** – wizualizacja danych (Streamlit / Dash)
  
# 🇬🇧 Log Analyzer (SIEM-lite)

## Project Description

**Log Analyzer (SIEM-lite)** is a lightweight Python-based log analyzer inspired by SIEM systems.  
It detects, classifies, and enriches security incidents in SSH logs with data from **Threat Intelligence APIs**.

The project integrates:

- Log file analysis (batch & real-time)
- Threat Intelligence (AbuseIPDB)
- RFC 5424 message generation + validation
- CSV / JSON exporting
- Syslog forwarding
- Asynchronous Syslog Receiver
- Syslog Pipeline
- PDF reporting

## Features

### Log Analysis
- Detection of failed SSH logins, root login attempts, brute-force attempts  
- Timestamp-aware windowing logic

### Real-time Monitoring
- Non-blocking monitoring using asyncio and aiofiles

### Threat Intelligence (AbuseIPDB)
- Automated IP reputation lookup  
- Cached results stored in SQLite

### Exporter Module
Exports alerts to:
- **CSV**
- **JSON**
- **Syslog (RFC 5424)**  
  Includes strict RFC 5424 validator.

### Syslog Receiver (UDP + TCP)
- Async UDP + TCP Syslog server  
- Supports **octet-counting framing (RFC 6587)**  
- Validates incoming messages with RFC 5424 validator  
- Forwards parsed alerts to LogsAnalyzer through SyslogPipeline

### Syslog Pipeline
- Parses RFC 5424 fields  
- Extracts timestamp, structured data, PID, app name, IP, and log message  
- Sends normalized alert objects to LogsAnalyzer

### PDF Reporting
- Generates structured PDF incident reports

### SQLite Persistence
Used to store:
- `failed_logins`
- `alerts_log`
- `cache` (Threat Intelligence data)

## Testing

Unit tests cover:
- Log analysis and brute-force logic
- Threat Intelligence API enrichment
- Exporter and Syslog message formatting

### Run tests

```bash
  pytest -v
```
### Code coverage report
```bash
  pytest --cov=src --cov-report=term-missing
```

## Project Structure
```
src/
 ├── main.py
 ├── log_analyzer.py
 ├── suspicious_patterns.py
 ├── failed_logins_db.py
 ├── threat_intel.py
 ├── exporter.py
 ├── generate_report.py
 └── utils.py
tests/
 ├── test_exporter.py
 └── test_suspicious_patterns.py
```

## Sample log
- `auth_sample_40.log` — contains 20 suspicious and 20 normal entries for testing.

## Requirements
- Python 3.10+

### Install dependencies

in root directory

```bash
  pip install -r requirements.txt
```

## How to Run

### To analyze specific logs file
```bash
  python -m src.main analyze --file ./samples/auth_sample_40.log --report
```

Performs:
- file analysis,
- IP reputation enrichment via Threat Intelligence API,
- generates `report.pdf`.

### Real-time monitoring
```bash
  python -m src.main analyze --realtime --paths test.log
```

Performs:
- real-time log stream monitoring,
- stores failed attempts in SQLite (`cache/failed_logins.db`),
- queries AbuseIPDB for IP reputation (cached),
- saves alerts to `alerts/alerts.json`.

## Data Structure
| Table | Description |
|--------|-------------|
| `failed_logins` | Records all failed login attempts |
| `alerts_log` | Stores last brute-force alert timestamps |
| `cache` | Stores cached Threat Intelligence data |

## Syslog Receiver

### Start Syslog Receiver
```bash
  python -m src.main syslog --udp-port 514 --tcp-port 514 --host 0.0.0.0
```

### Next steps
- Add **Machine Learning Anomaly Detection**
- Build **Web Dashboard** (Streamlit / Dash)
