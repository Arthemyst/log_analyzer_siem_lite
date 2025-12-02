# 🇵🇱 Log Analyzer (SIEM-lite)

## Opis projektu

**Log Analyzer (SIEM-lite)** to lekki analizator logów systemowych w Pythonie, inspirowany systemami klasy **SIEM (Security Information and Event Management)**.  
Narzędzie wykrywa i klasyfikuje potencjalne incydenty bezpieczeństwa w logach SSH, wzbogacając je o dane z zewnętrznych źródeł **Threat Intelligence**.

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
  - **Syslog (RFC 5424 compliant)** — możliwość wysyłania alertów do zewnętrznego serwera SIEM przez UDP/TCP.  
    (np. `send_syslog_alert(alert, server="127.0.0.1", port=514)`)

- **Generowanie raportów PDF**  
  Automatyczne tworzenie raportów z incydentami, danymi reputacyjnymi i znacznikami czasu.

- **Trwała baza SQLite**  
  Przechowuje:
  - próby logowania (`failed_logins`)
  - ostatnie alerty brute-force (`alerts_log`)
  - dane reputacyjne IP (`cache`)

## 🧪 Testy i pokrycie kodu

Projekt zawiera zestaw testów jednostkowych (`pytest`) obejmujący:
- analizę logów (`suspicious_patterns.py`)
- eksport danych (`exporter.py`)
- obsługę sysloga i walidację RFC 5424

### Uruchamianie testów

```bash
  pytest -v
```

### Sprawdzenie pokrycia testowego

```bash
  pytest --cov=src --cov-report=term-missing
```

Raport pokaże procentowe pokrycie testami oraz pliki, które wymagają dodatkowych testów.

## 🧩 Struktura projektu

```
src/
 ├── main.py                     # Główne CLI (typer)
 ├── log_analyzer.py             # Analiza plików i monitorowanie w czasie rzeczywistym
 ├── suspicious_patterns.py      # Wykrywanie brute-force i incydentów SSH
 ├── failed_logins_db.py         # Obsługa bazy SQLite
 ├── threat_intel.py             # Integracja z AbuseIPDB API
 ├── exporter.py                 # Eksport CSV / JSON / Syslog
 ├── generate_report.py          # Generowanie raportów PDF
 └── utils.py                    # Pomocnicze funkcje
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
  python src.main.py --file ./samples/auth_sample_40.log --generate-report
```

- analizuje plik logów,  
- wzbogaca dane o reputację IP,  
- generuje raport `report.pdf`.

### Monitorowanie logów w czasie rzeczywistym

```bash
  python src.main.py --realtime --paths test.log
```
- obserwuje plik logów w czasie rzeczywistym,  
- zapisuje próby logowania do SQLite (`cache/failed_logins.db`),  
- pobiera reputację IP z AbuseIPDB (cacheowane),  
- zapisuje alerty w `alerts/alerts.json`,  
- opcjonalnie wysyła alerty do serwera Syslog/

## Struktura danych (SQLite)
| Tabela | Opis |
|--------|------|
| `failed_logins` | Historia nieudanych logowań |
| `alerts_log` | Ostatnie alerty brute-force |
| `cache` | Bufor reputacji IP (Threat Intelligence) |

## Następne kroki
- **Machine Learning Anomaly Detection** – automatyczne wykrywanie nietypowych wzorców
- **Web Dashboard** – wizualizacja danych (Streamlit / Dash)
- **Syslog Receiver Module** – prosty odbiornik testowy dla alertów Syslog  
  
# 🇬🇧 Log Analyzer (SIEM-lite)

## Project Description

**Log Analyzer (SIEM-lite)** is a lightweight Python-based log analyzer inspired by SIEM systems.  
It detects, classifies, and enriches security incidents in SSH logs with data from **Threat Intelligence APIs**.

## Features

- **Real-time Log Monitoring** (`aiofiles`, `asyncio`)
- **Brute-force Detection** – detects ≥5 failed login attempts within a time window
- **Threat Intelligence API (AbuseIPDB)** – fetches IP reputation, cached locally
- **Exporter Module** – exports alerts to:
  - CSV
  - JSON
  - Syslog (RFC 5424 structured messages)
- **PDF Reporting** – generates detailed security incident reports
- **Persistent SQLite Storage** – stores login attempts, alerts, and cached intelligence data

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
  python src.main.py -file ./samples/auth_sample_40.log --generate-report
```

Performs:
- file analysis,
- IP reputation enrichment via Threat Intelligence API,
- generates `report.pdf`.

### To monitor logs in real time
```bash
  python src.main.py --realtime --paths test.log
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

### Next steps
- Add **Machine Learning Anomaly Detection**
- Build **Web Dashboard** (Streamlit / Dash)
- Develop **Syslog Receiver** for local testing
