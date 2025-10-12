# 🇵🇱 Log Analyzer (SIEM-lite)

## Opis projektu

**Log Analyzer (SIEM-lite)** to lekki analizator logów systemowych w Pythonie, inspirowany systemami klasy **SIEM (Security Information and Event Management)**.  
Narzędzie wykrywa i klasyfikuje potencjalne incydenty bezpieczeństwa w logach SSH, wzbogacając je o dane z zewnętrznych źródeł **Threat Intelligence**.

- Nieudane próby logowania (`Failed password`)

- Logowanie na konto root (`Accepted password for root`)

- Próby ataku typu brute-force (≥ 5 prób w krótkim czasie)

- Generowanie raportu z alertami do formatu **PDF**

## Funkcje

- **Monitorowanie logów w czasie rzeczywistym**  
  Asynchroniczny mechanizm śledzenia wpisów (`aiofiles`, `asyncio`).

- **Wykrywanie prób brute-force**  
  Analiza logów w oknach czasowych, wykrywanie ≥ 5 prób logowania w krótkim czasie.  
  Mechanizm pamięta ostatni alert dla danego użytkownika w bazie SQLite.

- **Integracja z Threat Intelligence APIs (AbuseIPDB)**  
  Automatyczne sprawdzanie reputacji adresów IP, zapis danych (kraj, ISP, liczba zgłoszeń, confidence score).  
  Dane są buforowane w lokalnej bazie SQLite, aby ograniczyć zapytania do API.

- **Raportowanie PDF**  
  Generowanie czytelnych raportów z wykrytymi incydentami i informacjami o reputacji źródeł.

- **Trwała baza SQLite**  
  Przechowuje historię nieudanych logowań, alertów brute-force i ocen reputacji IP.


## Przykładowy plik logów

- `auth_sample_40.log` — zawiera 20 podejrzanych i 20 prawidłowych wpisów do testowania działania analizera.

## Wymagania
- Python 3.10+

## Instalowanie zależności 
w `pip install -r requirements.txt`

## Jak uruchomić

### Analiza wybranego pliku z logami

w folderze src -> `python main.py --path-to-file [path to log file]`

ex. 

```bash
python main.py --path-to-file .\samples\auth_sample_40.log
```

To spowoduje:
- analizę pliku logów,  
- wzbogacenie alertów o dane reputacyjne (Threat Intelligence),  
- wygenerowanie raportu `report.pdf`.

### Monitorowanie logów w czasie rzeczywistym

w folderze src -> `python src/main.py --realtime [path to log file]`

ex.

```bash
python main.py --realtime --paths test.log
```

To spowoduje:

- śledzenie wpisów w czasie rzeczywistym,
  
- zapisywanie prób logowania w bazie `cache/failed_logins.db`,
  
- pobieranie reputacji IP z AbuseIPDB (cacheowane),
  
- zapisywanie alertów w `alerts/alerts.json`.

## Struktura danych

| Tabela | Opis |
|--------|------|
| `failed_logins` | Historia nieudanych logowań |
| `alerts_log` | Ostatnie alerty brute-force dla danego użytkownika |
| `cache` | Bufor reputacji IP (z Threat Intelligence API) |

## Następne kroki

- Moduł **Machine Learning Anomaly Detection**  
  (automatyczne wykrywanie nietypowych wzorców aktywności)
  
- **Interfejs webowy** z dashboardem (Streamlit / Dash)
  
# 🇬🇧 Log Analyzer (SIEM-lite)

## Project Description

**Log Analyzer (SIEM-lite)** is a lightweight Python-based log analyzer inspired by SIEM systems.  
It detects, classifies, and enriches security incidents in SSH logs with data from **Threat Intelligence APIs**.

## Features

- **Real-time Log Monitoring**  
  Asynchronous file watching using `aiofiles` and `asyncio`.

- **Brute-force Detection**  
  Detects ≥ 5 failed login attempts within a defined time window.  
  Persists last alert timestamps per user in SQLite to avoid duplicates.

- **Threat Intelligence API Integration (AbuseIPDB)**  
  Fetches IP reputation details (country, ISP, confidence score, total reports).  
  Cached locally in SQLite to reduce API requests.

- **PDF Alert Reporting**  
  Generates structured reports with enriched incident data and IP reputation.

- **Persistent SQLite Database**  
  Maintains failed logins, brute-force alerts, and threat intelligence cache.

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
in src directory -> `python main.py [path to log file]`

ex.

```bash
python main.py --path-to-file .\samples\auth_sample_40.log
```

Performs:

- file analysis,
  
- IP reputation enrichment via Threat Intelligence API,
  
- generates `report.pdf`.

### To monitor logs in real time
in src directory -> `python -m src.main  --realtime --paths test.log`

ex.

```bash
python main.py --realtime --paths test.log
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
