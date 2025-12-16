# 🇵🇱 Log Analyzer (SIEM-lite)

## Opis projektu

**Log Analyzer (SIEM-lite)** to projekt typu **blue-team / SOC**, który łączy klasyczną analizę logów, IDS (Network-based IDS), honeypot aplikacyjny oraz mechanizm korelacji zdarzeń – inspirowany architekturą systemów klasy **SIEM**.

Projekt zawiera:
- analizator logów,
- walidator RFC 5424,
- eksport danych (CSV / JSON / Syslog),
- asynchroniczny Syslog Receiver (UDP + TCP),
- pipeline łączący Syslog i Analyzer,
- generowanie raportów PDF,
- Honeypot HTTP (FastAPI),
- Dashboard wizualizacyjny (Streamlit).
- Network IDS (L3/L4) – analiza ruchu sieciowego, flow i anomalii
- Correlation Engine – łączenie zdarzeń z wielu źródeł w celu podniesienia wiarygodności alertów

## Architektura bezpieczeństwa

Projekt  ozdziela odpowiedzialności detekcji:

| Warstwa | Komponent | Zakres |
|------|---------|-------|
| L3/L4 | Network IDS | flow, port scans, timing, ML anomalies |
| L7 | HTTP Honeypot | payloady HTTP, path traversal, SQLi, XSS |
| SIEM | Correlation Engine | korelacja IDS + Honeypot |
| SOC | Dashboard / Reports | wizualizacja i analiza |

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

### Network IDS (Flow-based)
- przechwytywanie ruchu sieciowego (PyShark),
- agregacja pakietów do flow,
- detekcja:
  - anomalii (Isolation Forest),
  - skanów portów,
  - nietypowych zachowań sieciowych,
- eksport flow do JSONL.

### Machine Learning
- Isolation Forest (unsupervised),
- trening na rzeczywistych flow,
- runtime scoring nowych połączeń,
- regulowany próg anomalii.

### Dashboard (Streamlit)
- wizualizacja zdarzeń z Honeypota i Sysloga,
- statystyki, wykresy, podsumowania,
- analiza częstości ataków,
- ostatnie logi w formie tabel.

## Przykładowy scenariusz detekcji (IDS & honeypot)

1. Atak HTTP:
```
  curl http://127.0.0.1:8080/etc/passwd
```

2. Honeypot wykrywa **File Disclosure**
3. IDS rejestruje flow sieciowy
4. Correlation Engine łączy zdarzenia
5. Alert końcowy:
```json
{
  "type": "HONEYPOT_ATTACK",
  "attack_type": "File disclosure probe",
  "confidence": "VERY_HIGH",
  "severity": 7
}
```


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
├── app.py
├── generate_fake_data.py
└── requirements.txt
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
 ├── monitor.py       
 ├── utils.py  
 └── ids/
      ├── correlation_engine.py
      ├── detection_engine.py
      ├── flow_aggregator.py
      ├── flow_capture.py
      ├── honeypot_tail.py
      ├── ml_runtime_detector.py
      ├── realtime_flow_builder.py
      ├── scan_heuristic.py
      ml/
       ├── feature_config.py  
       └── train_model.py
honeypot/
 └── honeypot.py 
tests/
 ├── test_exporter.py
 ├── test_honeypot.py
 └── test_suspicious_patterns.py
 simulations/
 ├── send_test_syslog.py
 └── simulate_logs.py
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
```
  python -m src.main.py --file ./samples/auth_sample_40.log --report
```

- analizuje plik logów,  
- wzbogaca dane o reputację IP,  
- generuje raport `report.pdf`.
- opcjonalnie eksport do CSV/JSON

### Monitorowanie logów w czasie rzeczywistym

```
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
### IDS + honeypot

run IDS

```
  python src/ids/realtime_flow_builder.py --interface Wi-Fi --timeout 10 --interval 2 --threshold -0.5
```
run honeypot
```
  uvicorn honeypot.honeypot:app --host 0.0.0.0 --port
```
symulacja ataku

```
  curl http://127.0.0.1:8080/etc/passwd
```
 

# 🇬🇧 Log Analyzer (SIEM-lite)

## Project Description

**Log Analyzer (SIEM-lite)** is a **blue-team / SOC** type project that combines classic log analysis, IDS (Network-based IDS), an application honeypot, and an event correlation mechanism—inspired by **SIEM-class** system architectures.
The project integrates:

- log analyzer,
- RFC 5424 validator,
- data export (CSV / JSON / Syslog),
- asynchronous Syslog Receiver (UDP + TCP),
- pipeline connecting Syslog and Analyzer,
- PDF report generation,
- HTTP Honeypot (FastAPI),
- visualization dashboard (Streamlit),
- Network IDS (L3/L4) – network traffic, flow, and anomaly analysis,
- Correlation Engine – correlating events from multiple sources to increase alert confidence.

## Security Architecture

The project separates detection responsibilities:

| Layer | Component | Scope                                    |
|------|---------|------------------------------------------|
| L3/L4 | Network IDS | flow, port scans, timing, ML anomalies   |
| L7 | HTTP Honeypot | payloady HTTP, path traversal, SQLi, XSS |
| SIEM | Correlation Engine | IDS + Honeypot correlation               |
| SOC | Dashboard / Reports | visualization and analysis               |

## Features

### Log Analysis
- detection of failed logins,
- brute-force attempt detection,
- time-based pattern analysis,
- SSH incident classification.

### Real-time Monitoring
- log tracking using `asyncio` and `aiofiles`,
- automatic detection of new entries.

### Threat Intelligence (AbuseIPDB)
- IP address reputation lookup,
- SQLite cache limiting API requests.

### Alert Export
Three formats are supported:
- **CSV**
- **JSON**
- **Syslog RFC 5424**
  - structured message generation,
  - structure validation,
  - sending via UDP or TCP.

### Syslog Receiver (UDP + TCP)
- full Syslog support compliant with RFC 5424,
- TCP octet-framing support (RFC 6587),
- asynchronous UDP/TCP server,
- persistence of received events in `logs/received_syslog.log`.

### Syslog Pipeline
- RFC 5424 message parsing,
- extraction of: timestamp, hostname, procid, structured data, message,
- forwarding alerts to LogsAnalyzer.

### PDF Reports
- incident report generation,
- exported Threat Intelligence data.

### HTTP Honeypot (FastAPI)
- accepts arbitrary HTTP paths,
- reads payloads from requests,
- classifies attack types:
  - XSS,
  - SQL injection,
  - credential stuffing,
  - scans (wp-admin, phpMyAdmin),
  - LFI / file disclosure, etc.
- stores events in:
  - `logs/honeypot_events.jsonl`,
- generates Syslog RFC 5424 alerts.

### Network IDS (Flow-based)
- network traffic capture (PyShark),
- packet aggregation into flows,
- detection of:
  - anomalies (Isolation Forest),
  - port scans,
  - unusual network behavior,
- export of flows to JSONL.

### Machine Learning
- Isolation Forest (unsupervised),
- training on real network flows,
- runtime scoring of new connections,
- configurable anomaly threshold.

### Dashboard (Streamlit)
- visualization of Honeypot and Syslog events,
- statistics, charts, summaries,
- attack frequency analysis,
- recent logs displayed in tables.

## Example Detection Scenario (IDS & Honeypot)

1. HTTP attack:
```
curl http://127.0.0.1:8080/etc/passwd
```
2. Honeypot detects File Disclosure
3. IDS registers the network flow
4. Correlation Engine correlates events
5. Final alert:
```json
{
  "type": "HONEYPOT_ATTACK",
  "attack_type": "File disclosure probe",
  "confidence": "VERY_HIGH",
  "severity": 7
}
```


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
├── app.py
├── generate_fake_data.py
└── requirements.txt
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
 ├── monitor.py       
 ├── utils.py  
 └── ids/
      ├── correlation_engine.py
      ├── detection_engine.py
      ├── flow_aggregator.py
      ├── flow_capture.py
      ├── honeypot_tail.py
      ├── ml_runtime_detector.py
      ├── realtime_flow_builder.py
      ├── scan_heuristic.py
      ml/
       ├── feature_config.py  
       └── train_model.py
honeypot/
 └── honeypot.py 
tests/
 ├── test_exporter.py
 ├── test_honeypot.py
 └── test_suspicious_patterns.py
 simulations/
 ├── send_test_syslog.py
 └── simulate_logs.py
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
- generates `report.pdf`,
- optional export to CSV/JSON.

### Real-time monitoring
```
  python -m src.main analyze --realtime --paths test.log
```

Performs:
- real-time log stream monitoring,
- stores failed attempts in SQLite (`cache/failed_logins.db`),
- queries AbuseIPDB for IP reputation (cached),
- saves alerts to `alerts/alerts.json`,
- optionally sends alerts to a Syslog server.

## Database Data Structure
| Table | Description |
|--------|-------------|
| `failed_logins` | Records all failed login attempts |
| `alerts_log` | Stores last brute-force alert timestamps |
| `cache` | Stores cached Threat Intelligence data |

### Syslog Receiver (UDP + TCP)
```
  python -m src.main syslog --udp-port 514 --tcp-port 514 --host 0.0.0.0
```
The server supports:
- Syslog UDP (RFC 5424)
- Syslog TCP with framing (length-prefixed)
- pipeline integration

The pipeline automatically forwards alerts to:
- LogsAnalyzer
- exporter
- further processing (optional: Threat Intel, PDF, syslog forwarding)

### Honeypot
```
  uvicorn honeypot.honeypot:app --host 0.0.0.0 --port 8080
```

### Dashboard
```
  streamlit run dashboard/app.py
```

## Generating Sample Events

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
### IDS + honeypot

run IDS

```
python src/ids/realtime_flow_builder.py --interface Wi-Fi --timeout 10 --interval 2 --threshold -0.5
```
run honeypot
```
uvicorn honeypot.honeypot:app --host 0.0.0.0 --port
```
symulacja ataku

```
curl http://127.0.0.1:8080/etc/passwd
```
