## Log Analyzer (SIEM-lite)

### Opis projektu

To lekki analizator logów systemowych napisany w Pythonie, inspirowany funkcjonalnością prostego systemu SIEM (Security Information and Event Management).  
Narzędzie służy do wykrywania potencjalnych zagrożeń w logach SSH, takich jak:

- 🔐 Nieudane próby logowania (`Failed password`)
- ⚠️ Logowanie na konto root (`Accepted password for root`)
- 🚨 Próby ataku typu brute-force (≥ 5 prób w krótkim czasie)
- 📝 Generowanie raportu z alertami do formatu **PDF**

### Przykładowy plik logów
- `auth_sample_40.log` zawiera 20 podejrzanych i 20 prawidłowych wpisów do testowania.

### Wymagania
- Python 3.10+
- fpdf (raporty PDF)
- typer (komendy w terminale)

### Instalowanie zależności 
w 
`pip install -r requirements.txt`

### Jak uruchomić

w folderze src -> `python main.py [path to log file]`

np. `python main.py .\samples\auth_sample_40.log`

#### to spowoduje:

- przetworzenie pliku auth_sample_40.log

- wygenerowanie pliku report.pdf z wykrytymi incydentami

### Next steps

- przetwarzanie logów w czasie rzeczywistym
- witryna z wykresami do analizy danych

---

### Project Description
A lightweight system log analyzer written in Python, inspired by SIEM (Security Information and Event Management) tools.
It detects potential security threats in SSH logs, including:

- 🔐 Failed login attempts (Failed password)

- ⚠️ Successful root login events

- 🚨 Brute-force login patterns (≥ 5 attempts within short time)

- 📝 Generates a PDF report with alerts

### Sample log

- `auth_sample_40.log` contains 20 suspicious and 20 normal entries for testing.

### Requirements

- Python 3.10+
- fpdf (for PDF reports)
- typer (for terminal commands)

### Install dependencies
in root directory
`pip install -r requirements.txt`

### How to Run

in src directory -> `python main.py [path to log file]`

ex. `python main.py .\samples\auth_sample_40.log`

#### It will:

- process auth_sample_40.log

- generate report.pdf with detected incidents.

### Next steps

- real time logs processing
- website with dashboard to data analysis