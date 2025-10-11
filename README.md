## Log Analyzer (SIEM-lite)

### Opis projektu

To lekki analizator logów systemowych napisany w Pythonie, inspirowany funkcjonalnością prostego systemu SIEM (Security Information and Event Management).  
Narzędzie służy do wykrywania potencjalnych zagrożeń w logach SSH, takich jak:

- Nieudane próby logowania (`Failed password`)

- Logowanie na konto root (`Accepted password for root`)

- Próby ataku typu brute-force (≥ 5 prób w krótkim czasie)

- Generowanie raportu z alertami do formatu **PDF**

### Przykładowy plik logów
- `auth_sample_40.log` zawiera 20 podejrzanych i 20 prawidłowych wpisów do testowania.

### Wymagania
- Python 3.10+

### Instalowanie zależności 
w `pip install -r requirements.txt`

### Jak uruchomić

#### Analiza wybranego pliku z logami

w folderze src -> `python main.py [path to log file]`

np. `python main.py .\samples\auth_sample_40.log`

to spowoduje:

- przetworzenie pliku auth_sample_40.log

- wygenerowanie pliku report.pdf z wykrytymi incydentami

#### Monitorowanie logów w czasie rzeczywistym

w folderze src -> `python src/main.py --realtime`

to spowoduje:

- monitorowanie logów pojawiających się w pliku/plikach np. test.log

- zapisanie nieudanych prób logowania w cache (w celu wykrycia brute force nawet po zrestartowaniu analizera)
- zapisanie wyników w pliku alerts.json na potrzeby przyszłych analiz 


### Następne kroki

- zapisywanie logów w czasie rzeczywistym do bazy danych 
- witryna z wykresami do analizy danych

---

### Project Description
A lightweight system log analyzer written in Python, inspired by SIEM (Security Information and Event Management) tools.
It detects potential security threats in SSH logs, including:

- Failed login attempts (Failed password)

- Successful root login events

- Brute-force login patterns (≥ 5 attempts within short time)

- Generates a PDF report with alerts

### Sample log

- `auth_sample_40.log` contains 20 suspicious and 20 normal entries for testing.

### Requirements

- Python 3.10+

### Install dependencies
in root directory
`pip install -r requirements.txt`

### How to Run
#### To analyze specific logs file
in src directory -> `python main.py [path to log file]`

ex. `python main.py --path-to-file .\samples\auth_sample_40.log`

It will:

- process auth_sample_40.log

- generate report.pdf with detected incidents.

#### To monitor logs in real time
in src directory -> `python src/main.py --realtime`

It will:

- monitor logs appeared in logs file ex. test.log
- save failed logs into cache
- save details into alerts.json

### Next steps

- real time logs processing
- saving real time logs to the database 
- website with dashboard to data analysis
