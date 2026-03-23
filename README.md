# NSR – Network Sniffer Reporting

ARCHITECTURE

1. Ogólny schemat działania

NSR składa się z trzech głównych warstw:

1)  Warstwa interfejsu użytkownika
    -   GUI (GUI.py)
    -   CLI (CLI.py)
2)  Warstwa logiki aplikacji
    -   main.py
3)  Warstwa systemowa / zewnętrzna
    -   Nmap
    -   System plików
    -   Serwer SMTP

2. Przepływ działania aplikacji

Użytkownik (GUI / CLI) ↓ main.py 
                ↓
┌───────────────┬────────────────┬──────────────┐ 
│               │                │              │ 
Nmap        Generowanie PDF     SMTP         Pliki JSON 
│               │                │              │ 
↓               ↓                ↓              ↓ 
Wyniki → hosts.json → raport.pdf → wysyłka → archive.json

3. Moduły aplikacji

GUI (GUI.py) - Interfejs graficzny (Tkinter) - Obsługa przycisków:
Start/Stop, raport, e-mail, archiwum, logi - Korzysta z funkcji main.py

CLI (CLI.py) - Interfejs terminalowy - Obsługa komend (scan, report,
archive, logs, send-test-mail) - Współdzieli logikę z GUI

Warstwa logiki (main.py) - Uruchamianie Nmap - Analiza wyników -
Aktualizacja hosts.json - Generowanie raportów PDF (ReportLab) -
Wysyłanie e-mail (SMTP) - Archiwizacja danych - Logowanie zdarzeń

4. System plików

conf.json – konfiguracja aplikacji hosts.json – aktualny stan hostów
archive.json – historia raportów log.json – logi systemowe raporty/ –
wygenerowane raporty PDF

5. Mechanizm skanowania

1.  Wywołanie Nmap przez python-nmap

2.  Parsowanie wyników do JSON

3.  Porównanie z poprzednim stanem

4.  Wykrywanie zmian (nowe hosty, zmiany portów)

5.  Zapis danych lokalnie

6.  Generowanie raportu

-   Pobranie danych z hosts.json
-   Generowanie PDF przy użyciu ReportLab
-   Zapis do katalogu raportów
-   Opcjonalna wysyłka e-mail

7. Mechanizm wysyłki e-mail

1.  Wczytanie konfiguracji SMTP z conf.json

2.  Utworzenie wiadomości MIME

3.  Dołączenie załączników

4.  Połączenie TLS z serwerem SMTP

5.  Wysłanie wiadomości

6.  Architektura warstwowa

+---------------------------+
|        GUI / CLI          |
+---------------------------+

              |
              v

+---------------------------+
|         main.py           |
|                           |
| -   scan_network()        |
| -   generate_report()     |
| -   send_email()          |
| -   archive_data()        |
+---------------------------+

           |
  -------------------
         | | |
         v v v
   ap ReportLab SMTP

9. Założenia projektowe

-   Jedna wspólna warstwa logiki dla GUI i CLI
-   Brak duplikacji kodu
-   Konfiguracja w pliku JSON
-   Możliwość spakowania do jednej binarki (PyInstaller)
-   Obsługa Linux i Windows
