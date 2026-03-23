#!/usr/bin/env python3
# CLI.py - terminalowy interfejs do Network Sniffer Reporting
import argparse
import json
import os
import sys

from main import (
    skanuj_siec,
    generuj_raport_pdf,
    load_conf,
    save_conf,
    start_scheduler,
    stop_scheduler,
    wczytaj_archiwum,
    zapisz_archiwum,
    LOG_FILE
)

CONF_FILE = "conf.json"
DEF_CONF_FILE = "def_conf.json"

def show_config():
    conf = load_conf()
    print(json.dumps(conf, indent=4, ensure_ascii=False))

def edit_config(args):
    conf = load_conf()
    if args.siec:
        conf["siec"] = args.siec
    if args.interwal is not None:
        conf["interwal"] = args.interwal
    if args.godzina:
        conf["godzina_raportu"] = args.godzina
    if args.raport_dir:
        conf["raport_dir"] = args.raport_dir
    if args.nmap_path:
        conf["nmap_path"] = args.nmap_path
    if args.recipient_email:
        conf["recipient_email"] = args.recipient_email
    if args.sender_email:
        conf["sender_email"] = args.sender_email
    if args.sender_password:
        conf["sender_password"] = args.sender_password
    if args.smtp_server:
        conf["smtp_server"] = args.smtp_server
    if args.smtp_port:
        conf["smtp_port"] = args.smtp_port
    if args.smtp_tls:
        conf["smtp_tls"] = args.smtp_tls

    save_conf(conf)
    print("✅ Zapisano nową konfigurację.")

def reset_defaults():
    if os.path.exists(DEF_CONF_FILE):
        with open(DEF_CONF_FILE, "r", encoding="utf-8") as f:
            conf = json.load(f)
        save_conf(conf)
        print("✅ Przywrócono ustawienia domyślne.")
    else:
        print("❌ Brak pliku def_conf.json.")

def show_logs():
    if not os.path.exists(LOG_FILE):
        print("❌ Brak logów.")
        return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except Exception as e:
        print(f"❌ Błąd odczytu logów: {e}")
        return

    for log in logs:
        time = log.get("time", "-")
        level = log.get("level", "-")
        msg = log.get("message", "")
        print(f"[{time}] ({level}) {msg}")

def show_archive():
    archiwum = wczytaj_archiwum()
    print(json.dumps(archiwum, indent=4, ensure_ascii=False))

def edit_host(args):
    arch = wczytaj_archiwum()
    if args.host in arch:
        arch[args.host]["name_host"] = args.name
        zapisz_archiwum(arch)
        print(f"✅ Zmieniono nazwę hosta {args.host} na {args.name}")
    else:
        print(f"❌ Host {args.host} nie istnieje w archiwum.")

def run_scan_with_optional_network(network=None):
    """
    Jednorazowe skanowanie sieci (z opcjonalnym własnym zakresem).
    Po skanowaniu generuje raport PDF, ale nie usuwa historii.
    """
    if not network:
        print("Rozpoczynam skanowanie sieci (konfiguracja z conf.json)...")
        skanuj_siec()
        print("Skanowanie zakończone. Generuję raport...")
        generuj_raport_pdf(z_wym_raport=True)
        print("✅ Raport zapisany.")
        return

    # backup konfiguracji
    try:
        conf_backup = load_conf()
    except Exception as e:
        print(f"❌ Nie udało się wczytać konfiguracji: {e}")
        return

    conf_tmp = conf_backup.copy()
    conf_tmp["siec"] = network

    try:
        save_conf(conf_tmp)
        print(f"Rozpoczynam skanowanie sieci: {network} (tymczasowe ustawienie)...")
        skanuj_siec()
        print("Skanowanie zakończone. Generuję raport...")
        generuj_raport_pdf(z_wym_raport=True)
        print("✅ Raport zapisany.")
    except Exception as e:
        print(f"❌ Błąd podczas skanowania: {e}")
    finally:
        try:
            save_conf(conf_backup)
        except Exception as e:
            print(f"❌ Ostrzeżenie: nie udało się przywrócić oryginalnej konfiguracji: {e}")

# ==============================
# Tryb interaktywny (menu)
# ==============================
def interactive_menu():
    while True:
        print("\n===== Network Sniffer Reporting (CLI) =====")
        print("1. Skanuj sieć")
        print("2. Wygeneruj raport PDF (bieżący)")
        print("3. Wygeneruj raport PDF (archiwum)")
        print("4. Uruchom scheduler")
        print("5. Zatrzymaj scheduler")
        print("6. Pokaż logi")
        print("7. Pokaż archiwum hostów")
        print("8. Pokaż konfigurację")
        print("9. Edytuj konfigurację")
        print("10. Edytuj nazwę hosta")
        print("11. Reset ustawień domyślnych")
        print("0. Wyjście")

        choice = input("Wybierz opcję: ").strip()

        if choice == "1":
            use_custom = input("Podać niestandardową sieć/IP (CIDR)? (t/n): ").strip().lower()
            if use_custom in ("t", "y", "tak", "yes"):
                network = input("Wpisz sieć w formacie IP/CIDR (np. 192.168.50.0/24): ").strip()
                if network:
                    run_scan_with_optional_network(network)
                else:
                    print("❌ Nie podano sieci. Pomiń.")
            else:
                run_scan_with_optional_network(None)
        elif choice == "2":
            generuj_raport_pdf(z_wym_raport=True)
        elif choice == "3":
            generuj_raport_pdf(z_archiwum=True)
        elif choice == "4":
            start_scheduler()
        elif choice == "5":
            stop_scheduler()
        elif choice == "6":
            show_logs()
        elif choice == "7":
            show_archive()
        elif choice == "8":
            show_config()
        elif choice == "9":
            siec = input("Nowa sieć (ENTER aby pominąć): ")
            interwal = input("Nowy interwał minut (ENTER aby pominąć): ")
            godzina = input("Godzina raportu HH:MM (ENTER aby pominąć): ")
            raport_dir = input("Folder raportów (ENTER aby pominąć): ")
            nmap_path = input("Ścieżka do nmap (ENTER aby pominąć): ")
            recipient = input("Email odbiorcy (ENTER aby pominąć): ")
            sender = input("Email nadawcy (ENTER aby pominąć): ")
            passwd = input("Hasło nadawcy (ENTER aby pominąć): ")
            smtp_server = input("Podaj server smtp (ENTER aby pominąć): ")
            smtp_port = int(input("Podaj server smtp port (ENTER aby pominąć: "))
            smtp_tls = input("Podaj czy wiadomości mają być szyfrowane (true/false) (ENTER aby pominąć): ").lower()

            class Args: pass
            args = Args()
            args.siec = siec or None
            args.interwal = int(interwal) if interwal else None
            args.godzina = godzina or None
            args.raport_dir = raport_dir or None
            args.nmap_path = nmap_path or None
            args.recipient_email = recipient or None
            args.sender_email = sender or None
            args.sender_password = passwd or None
            args.smtp_server = smtp_server or None
            args.smtp_port = smtp_port or None
            if smtp_tls in ("t", "y", "tak", "yes", "true"):
                args.smtp_tls = smtp_tls
            else:
                args.smtp_tls = False

            edit_config(args)
        elif choice == "10":
            host = input("Podaj MAC/IP hosta: ")
            name = input("Podaj nową nazwę hosta: ")

            class Args: pass
            args = Args()
            args.host = host
            args.name = name
            edit_host(args)
        elif choice == "11":
            reset_defaults()
        elif choice == "0":
            print("👋 Zamykanie programu...")
            break
        else:
            print("❌ Nieprawidłowa opcja.")

# ==============================
# Główna funkcja (argparse)
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description="Network Sniffer Reporting (CLI)"
    )
    sub = parser.add_subparsers(dest="command", help="Dostępne polecenia")

    scan_p = sub.add_parser("scan", help="Wykonaj skanowanie sieci (opcjonalnie: --siec IP/CIDR)")
    scan_p.add_argument("--siec", "-s", help="Adres sieci w formacie CIDR (np. 192.168.1.0/24)")

    sub.add_parser("report", help="Wygeneruj raport PDF z bieżącej historii")
    sub.add_parser("report-arch", help="Wygeneruj raport PDF z archiwum")
    sub.add_parser("start", help="Uruchom scheduler")
    sub.add_parser("stop", help="Zatrzymaj scheduler")
    sub.add_parser("logs", help="Wyświetl logi")
    sub.add_parser("archive", help="Wyświetl archiwum hostów")
    sub.add_parser("config", help="Pokaż aktualną konfigurację")
    sub.add_parser("reset", help="Przywróć ustawienia domyślne")

    edit_conf = sub.add_parser("edit-config", help="Edytuj konfigurację")
    edit_conf.add_argument("--siec", help="Adres sieci w formacie CIDR (np. 192.168.1.0/24)")
    edit_conf.add_argument("--interwal", type=int, help="Interwał skanowania w minutach")
    edit_conf.add_argument("--godzina", help="Godzina raportu w formacie HH:MM")
    edit_conf.add_argument("--raport-dir", help="Folder, w którym zapisywane są raporty")
    edit_conf.add_argument("--nmap-path", help="Ścieżka do programu nmap")
    edit_conf.add_argument("--recipient-email", help="Adres email odbiorcy raportów")
    edit_conf.add_argument("--sender-email", help="Adres email nadawcy")
    edit_conf.add_argument("--sender-password", help="Hasło do emaila nadawcy")
    edit_conf.add_argument("--smtp-server", help="Server pocztowy smtp")
    edit_conf.add_argument("--smtp-port", help="Port smtp poczty elektronicznej")
    edit_conf.add_argument("--smtp-tls", help="Zgoda na szyfrowanie wiadomości")

    edit_h = sub.add_parser("edit-host", help="Edytuj nazwę hosta w archiwum")
    edit_h.add_argument("host", help="MAC/IP hosta")
    edit_h.add_argument("name", help="Nowa nazwa hosta")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        interactive_menu()
        return

    if args.command == "scan":
        run_scan_with_optional_network(getattr(args, "siec", None))
    elif args.command == "report":
        generuj_raport_pdf(z_wym_raport=True)
    elif args.command == "report-arch":
        generuj_raport_pdf(z_archiwum=True)
    elif args.command == "start":
        start_scheduler()
    elif args.command == "stop":
        stop_scheduler()
    elif args.command == "logs":
        show_logs()
    elif args.command == "archive":
        show_archive()
    elif args.command == "config":
        show_config()
    elif args.command == "edit-config":
        edit_config(args)
    elif args.command == "edit-host":
        edit_host(args)
    elif args.command == "reset":
        reset_defaults()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
