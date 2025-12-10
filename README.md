# 🇵🇱 Log Analyzer (SIEM-lite)

## Opis projektu

**Log Analyzer (SIEM-lite)** to lekki analizator logów systemowych w Pythonie, inspirowany systemami klasy **SIEM (Security Information and Event Management)**.  
Projekt wykrywa i klasyfikuje potencjalne incydenty bezpieczeństwa w logach, wzbogaca je o dane zewnętrzne (Threat Intelligence), przetwarza komunikaty Syslog i umożliwia ich wizualizację dzięki panelowi dashboard.

Projekt zawiera:
- analizator logów,
- walidator RFC 5424,
- eksport danych (CSV / JSON / Syslog),
- asynchroniczny Syslog Receiver (UDP + TCP),
- pipeline łączący Syslog i Analyzer,
- generowanie raportów PDF,
- Honeypot HTTP (FastAPI),
- Dashboard wizualizacyjny (Streamlit).

## Funkcje

### Analiza logów
- wykrywanie nieudanych logowań,
- detekcja prób brute-force,
- analiza wzorców w czasie,
- klasyfikacja incydentów SSH.

### Monitorowanie w czasie rzeczywistym
- śledzenie logów z wykorzystaniem `asyncio` i `aiofiles`,
- automatyczne wykrywanie nowych wpisów.

### Threat Intelligence (AbuseIPDB)
- pobieranie reputacji adresów IP,
- cache w SQLite ograniczający zapytania do API.

### Eksport alertów
Obsługiwane są 3 formaty:
- **CSV**
- **JSON**
- **Syslog RFC 5424**
  - generowanie strukturalnych komunikatów,
  - walidacja struktury,
  - wysyłanie przez UDP lub TCP.

### Syslog Receiver (UDP + TCP)
- pełna obsługa Syslog w standardzie RFC 5424,
- wsparcie TCP octet-framing (RFC 6587),
- asynchroniczny serwer UDP/TCP,
- zapis odebranych zdarzeń do `logs/received_syslog.log`.

### Syslog Pipeline
- parsowanie wiadomości RFC 5424,
- ekstrakcja: timestamp, hostname, procid, structured data, message,
- przekazywanie alertów do LogsAnalyzer.

### Raporty PDF
- generacja raportów incydentów,
- eksportowane dane z Threat Intelligence.

### HTTP Honeypot (FastAPI)
- przyjmuje dowolne ścieżki HTTP,
- odczytuje payloady z żądań,
- klasyfikuje typ ataku:
  - XSS,
  - SQL injection,
  - credential stuffing,
  - scans (wp-admin, phpMyAdmin),
  - LFI / file disclosure itd.
- zapisuje zdarzenia do:
  - `logs/honeypot_events.jsonl`,
- generuje alert Syslog RFC 5424.

### Dashboard (Streamlit)
- wizualizacja zdarzeń z Honeypota i Sysloga,
- statystyki, wykresy, podsumowania,
- analiza częstości ataków,
- ostatnie logi w formie tabel.

## Testy i pokrycie kodu

Projekt zawiera zestaw testów jednostkowych (`pytest`) obejmujący:
- analizy logów i wykrywania incydentów
- eksportera (CSV/JSON/Syslog)
- walidacji RFC 5424
- integracji parsowania

### Uruchamianie testów

```
  pytest -v
```

### Sprawdzenie pokrycia testowego

```
  pytest --cov=src --cov-report=term-missing
```

Raport pokaże procentowe pokrycie testami oraz pliki, które wymagają dodatkowych testów.

## Struktura projektu

```
src/
 ├── main.py                 
 ├── logs_analyzer.py        
 ├── suspicious_patterns.py  
 ├── failed_logins_db.py     
 ├── threat_intel.py         
 ├── exporter.py             
 ├── syslog_receiver.py      
 ├── syslog_pipeline.py      
 ├── generate_report.py      
 └── utils.py                
honeypot/
 └── honeypot.py 
dashboard/
 └── app.py 
tests/
 ├── test_exporter.py
 ├── test_honeypot.py
 └── test_suspicious_patterns.py
```

## Przykładowy plik logów

- `auth_sample_40.log` — zawiera 20 podejrzanych i 20 prawidłowych wpisów do testowania działania analizera.

## Wymagania
- Python 3.10+

## Instalowanie zależności
``` 
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
  python -m src.main analyze --realtime --paths test.log
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

## Honeypot (FastAPI)

```
  uvicorn honeypot.honeypot:app --host 0.0.0.0 --port 8080
```

## Dashboard (Streamlit)

```
  streamlit run dashboard/app.py
```

## Generowanie przykładowych zdarzeń

### Honeypot
```
  curl http://localhost:8080/wp-admin
  curl -X POST http://localhost:8080/login -d "username=admin&password=admin"
  curl http://localhost:8080/etc/passwd
```

### Syslog
python
```
from src.exporter import send_syslog_alert
send_syslog_alert({"source": "10.0.0.123", "alert": "Test alert", "pid": 111})
```


## Następne kroki
- **Machine Learning Anomaly Detection** – automatyczne wykrywanie nietypowych wzorców
- Integracja Reguł IDS
  
# 🇬🇧 Log Analyzer (SIEM-lite)

## Project Description

**Log Analyzer (SIEM-lite)** is a lightweight Python-based log analyzer inspired by SIEM systems.  
It detects, classifies, and enriches security incidents in SSH logs with data from **Threat Intelligence APIs**.

The project integrates:

- Log file analysis (batch & real-time),
- Threat Intelligence (AbuseIPDB),
- RFC 5424 message generation + validation,
- CSV / JSON / RFC 5424 Syslog exporting,
- Strict RFC 5424 validator,
- Asynchronous Syslog Receiver (UDP + TCP),
- Syslog Pipeline,
- PDF reporting,
- HTTP Honeypot (FastAPI),
- Data visualization dashboard (Streamlit).

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

### FastAPI HTTP Honeypot
- catches arbitrary HTTP traffic,
- captures payloads and metadata,
- performs attack classification,
- logs to JSONL + Syslog.

### Streamlit Dashboard
- presents Honeypot + Syslog activity,
- charts and tables,
- real-time analytics.

## Testing

Unit tests cover:
- Log analysis and brute-force logic
- Threat Intelligence API enrichment
- Exporter and Syslog message formatting

### Run tests

```
  pytest -v
```
### Code coverage report
```
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
honeypot/
 └── honeypot.py # FastAPI Honeypot
dashboard/
 └── app.py # Streamlit dashboard
tests/
 ├── test_exporter.py
 ├── test_honeypot.py
 └── test_suspicious_patterns.py
```

## Sample log
- `auth_sample_40.log` — contains 20 suspicious and 20 normal entries for testing.

## Requirements
- Python 3.10+

### Install dependencies

in root directory

```
  pip install -r requirements.txt
```

## How to Run

### To analyze specific logs file
```
  python -m src.main analyze --file ./samples/auth_sample_40.log --report
```

Performs:
- file analysis,
- IP reputation enrichment via Threat Intelligence API,
- generates `report.pdf`.

### Real-time monitoring
```
  python -m src.main analyze --realtime --paths test.log
```

Performs:
- real-time log stream monitoring,
- stores failed attempts in SQLite (`cache/failed_logins.db`),
- queries AbuseIPDB for IP reputation (cached),
- saves alerts to `alerts/alerts.json`.

### Syslog Receiver
```
  python -m src.main syslog --udp-port 514 --tcp-port 514 --host 0.0.0.0
```

### Honeypot
```
  uvicorn honeypot.honeypot:app --host 0.0.0.0 --port 8080
```

### Dashboard
```
  streamlit run dashboard/app.py
```

## Database Data Structure
| Table | Description |
|--------|-------------|
| `failed_logins` | Records all failed login attempts |
| `alerts_log` | Stores last brute-force alert timestamps |
| `cache` | Stores cached Threat Intelligence data |

### Next steps
- Add **Machine Learning Anomaly Detection**
- IDS system
