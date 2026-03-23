###--- BIBLIOTEKI ---###
import os
import json
import smtplib
import nmap
import schedule
import time
import threading

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


###--- PLIKI ZEWNĘTRZNE ---###
CONF_FILE = "conf.json"
DEF_CONF_FILE = "def_conf.json"
HISTORIA_FILE = "hosts.json"
ARCHIWUM_FILE = "archive.json"
LOG_FILE = "log.json"

###--- FLAGI ---###
schedule_running = False
_schedule_thread = None

###--- LOGI SYSTEMOWE I KOMUNIKATY ---###
def log_message(msg, level="system"):
    log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "message": msg
    }

    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

###--- KONFIGURACJA ---###
def load_conf():
    if os.path.exists(CONF_FILE):
        with open(CONF_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    with open(DEF_CONF_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_conf(conf):
    with open(CONF_FILE, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=4, ensure_ascii=False)

###--- HISTORIA ---###
def wczytaj_historie():
    if os.path.exists(HISTORIA_FILE):
        with open(HISTORIA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def zapisz_historie(historia):
    with open(HISTORIA_FILE, "w", encoding="utf-8") as f:
        json.dump(historia, f, indent=4, ensure_ascii=False)

def wczytaj_archiwum():
    if not os.path.exists(ARCHIWUM_FILE):
        log_message(f"Archiwum", f"Brak archiwum")
        return {}
    with open(ARCHIWUM_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def update_arch(host, arch_host):
    remove_key = []
    for key, data in host.items():
        for key_arch, data_arch in arch_host.items():
            if key == key_arch:
                data_arch["mac"] = data["mac"]
                data_arch["last_seen"] = data["last_seen"]
                data_arch["events"] = data_arch["events"] + data["events"]
                data_arch["ips"] = list(set(data_arch["ips"]+data["ips"]))
                data_arch["os"] = data["os"]
                data_arch["running"] = data["running"]
                remove_key.append(key)
    for key in remove_key:
        del host[key]
    arch_host.update(host)
    return arch_host

def zapisz_archiwum(archiwum):
    with open(ARCHIWUM_FILE, "w", encoding="utf-8") as f:
        json.dump(archiwum, f, indent=4, ensure_ascii=False)

###--- EMAIL ---###
def send_email(recipient, files):
    if not recipient:
        return

    conf = load_conf()

    sender = conf["sender_email"]
    password = conf["sender_password"]

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = f"Scan reporting from your network {conf['siec']}"
    body = f"W załączniku znajdują się wygenrowane raportu. Proszę nie odpowiadać na tę wiadomość. Wiadomość jest automatyczna."
    msg.attach(MIMEText(body, "plain"))
    for file in files:
        try:
            with open(file, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(file)}")

                msg.attach(part)
        except Exception as e:
            log_message(f"Błąd załącznika {file}: {e}", level="error")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
        log_message(f"Wysłano raport email na {recipient}", level="system")
    except Exception as e:
        log_message(f"Błąd wysyłania e-mail: {e}", level="error")

###--- POBRANIE MAC PRZEZ SCAPY ---###
def pobierz_mac_scapy(ip, iface=None):
    try:
        pakiet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        odpowiedzi, _ = srp(pakiet, timeout=5, verbose=False, iface=iface)
        for _, odp in odpowiedzi:
            return odp.hwsrc
    except Exception as e:
        log_message(f"Błąd pobierania MAC przez SCAPY: {e}", level="error")
    return None

###--- SKANOWANIE SIECI ---###
def skanuj_siec():
    print("Skanuje sieć")
    conf = load_conf()
    aktualny_czas = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    historia = wczytaj_historie()
    archiwum = wczytaj_archiwum()

    nm = nmap.PortScanner(nmap_search_path=(conf["nmap_path"],))
    nm.scan(hosts=conf["siec"], arguments="-sT -O --osscan-guess -Pn")

    aktywne_hosts = []

    for ip in nm.all_hosts():
        mac = nm[ip]["addresses"].get("mac")
        if not mac:
            mac = pobierz_mac_scapy(ip)
        os_name = "Nieznany"
        running = "Nieznany"
        if "osmatch" in nm[ip] and nm[ip]["osmatch"]:
            os_name = nm[ip]["osmatch"][0]["name"]
            if "osclass" in nm[ip]["osmatch"][0]["osclass"]:
                os_classes = nm[ip]["osmatch"][0]["osclass"]
                if os_classes: running = os_classes[0].get("osfamily", "Nieznany")
        key = mac if mac else ip
        aktywne_hosts.append(key)

        if key not in historia:
            first_seen = aktualny_czas
            if key in archiwum:
                first_seen = archiwum[key].get("first_seen", aktualny_czas)
            historia[key] = {
                "mac": mac if mac else "Brak",
                "name_host": "",
                "first_seen": first_seen,
                "last_seen": aktualny_czas,
                "ips": [ip],
                "os": os_name,
                "running": running,
                "events": [{"status": "Aktywny", "time": aktualny_czas, "ip": ip}]
            }
        else:
            dane = historia[key]
            dane["last_seen"] = aktualny_czas
            if ip not in dane["ips"]:
                dane["ips"].append(ip)
                dane["events"].append({"status": "IP zmienione", "time": aktualny_czas, "ip": ip})
            if os_name != "Nieznany":
                dane["os"] = os_name
            if running != "Nienznay":
                dane["running"] = running
            if dane["events"][-1]["status"] != "Aktywny":
                dane["events"].append({"status": "Aktywny", "time": aktualny_czas, "ip": ip})
    for key, dane in historia.items():
        if key not in aktywne_hosts:
            dane["last_seen"] = aktualny_czas
            if dane["events"][-1]["status"] != "Nieaktywny":
                dane["events"].append({"status": "Niaktywny", "time": aktualny_czas})
    zapisz_historie(historia)
    log_message(f"Skan zakończony - aktywne hosty: {len(aktywne_hosts)}", level="system")

###--- RAPORT PDF ---###
def generuj_raport_pdf(z_archiwum=False, z_wym_raport=False):
    conf = load_conf()
    historia = wczytaj_archiwum() if z_archiwum else wczytaj_historie()

    if not historia:
        log_message(f"Brak danych do raportu", level="system")
        return
    os.makedirs(conf["raport_dir"], exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    styles = getSampleStyleSheet()

    ###--- SZCZEGÓŁOWY ---###
    pdf_file_szcz = os.path.join(conf["raport_dir"], f"raport_szczegolowy_{timestamp}.pdf")
    doc = SimpleDocTemplate(pdf_file_szcz, pagesize=A4)

    elements = []
    elements.append(Paragraph(f"Raport szczególowy skanowania sieci {conf['siec']}", styles["Title"]))
    elements.append(Spacer(1, 12))

    for key, dane in historia.items():
        elements.append(Paragraph(f"Host: {key}", styles["Heading2"]))
        elements.append(Paragraph(f"Nazwa: {dane.get('name_host', "")}", styles["Normal"]))
        elements.append(Paragraph(f"OS: {dane.get('os','Nieznany')})({dane.get('runing','Nieznany')})",styles["Normal"]))

        if z_archiwum:
            elements.append(Paragraph(f"Pierwszy raz: {dane['first_seen']}", styles["Normal"])),
        else:
            historia_arch = wczytaj_archiwum()
            for key_arch, dane_arch in historia_arch.items():
                if key_arch == key:
                    if dane_arch["first_seen"]:
                        elements.append(Paragraph(f"Pierwszy raz: {dane_arch['first_seen']}", styles["Normal"])),
                    else:
                        elements.append(Paragraph(f"Pierwszy raz: {dane['first_seen']}", styles["Normal"])),

        elements.append(Paragraph(f"Ostatni raz: {dane['last_seen']}", styles["Normal"]))
        elements.append(Paragraph(f"Adresy IP: {', '.join(dane['ips'])}", styles["Normal"]))
        elements.append(Spacer(1, 8))

        data = [["Status", "Czas", "IP"]]
        for ev in dane["events"]:
            data.append([ev["status"], ev["time"], ev.get("ip", "-")])

        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACGRAUND", (0,0), (-1,0), colors.lightgrey),
            ("ALIGN", (0,0), (-1, -1), "CENTER"),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey)
        ]))

        elements.append(table)
        elements.append(Spacer(1, 16))
    doc.build(elements)

    ###--- ZBIORCZY ---###
    pdf_file_zbior = os.path.join(conf["raport_dir"], f"raport_zbiorczy_{timestamp}.pdf")
    doc = SimpleDocTemplate(pdf_file_zbior, pagesize=landscape(A4))

    elements = []
    elements.append(Paragraph(f"Raport zbiorczy skanowania sieci {conf['siec']}", styles["Title"]))
    elements.append(Spacer(1, 12))

    para_style = ParagraphStyle(name="TableCell", fontSize=7, leading=9, aligment=1)
    data = [["Host", "Nazwa", "OS", "Pierwszy raz", "Ostatni raz", "Status", "IP-lista"]]
    for key, dane in historia.items():

        first_seen_temp = ""

        if z_archiwum:
            first_seen_temp = dane["first_seen"]
        else:
            historia_arch = wczytaj_archiwum()
            for key_arch, dane_arch in historia_arch.items():
                if key_arch == key:
                    if dane_arch["first_seen"]:
                        first_seen_temp = dane_arch["first_seen"]
                    else:
                        first_seen_temp = dane["first_seen"]

        last_status = dane["events"][-1]["status"]
        ip_list_para = Paragraph("<br/>".join(dane["ips"]), para_style)
        data.append([
            key,
            f"{dane.get('name_host','')}",
            f"{dane.get('os', 'Nieznany')}({dane.get('running','Nieznany')})",
            first_seen_temp,
            dane["last_seen"],
            last_status,
            ip_list_para
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACGRAUND", (0, 0), (-1, 0), colors.lightgrey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(table)
    doc.build(elements)

    log_message(f"Wygenerowano raporty: {pdf_file_szcz}, {pdf_file_zbior}", level="system")

    if conf["recipient_email"] != "":
        if conf["sender_email"] != "":
            if conf["sender_password"] != "":
                send_email(conf.get("recipient_email", ""), [pdf_file_szcz, pdf_file_zbior])
            else:
                log_message(f"Nie wysłano raportów. Uzupełnij dane do wysyłki.", level="system")

    if not z_archiwum:
        if not z_wym_raport:
            historia_biez = wczytaj_historie()
            archiwum = wczytaj_archiwum()
            if not archiwum or archiwum == "{}":
                archiwum.update(historia_biez)
                zapisz_archiwum(archiwum)
                print("Not Archiwum")
            else:
                zapisz_archiwum(update_arch(historia_biez, archiwum))
                print("Z Archiwum")
            zapisz_historie({})

###--- HARMONOGRAM ---###
def scheduler_loop():
    global schedule_running
    while schedule_running:
        schedule.run_pending()
        time.sleep(1)

def start_scheduler():
    global schedule_running, _schedule_thread
    if schedule_running:
        return

    conf = load_conf()
    schedule.every(conf["interwal"]).minutes.do(skanuj_siec)
    schedule.every().day.at(conf["godzina_raportu"]).do(skanuj_siec)
    schedule.every().day.at(conf["godzina_raportu"]).do(generuj_raport_pdf)
    schedule_running = True
    _schedule_thread = threading.Thread(target=scheduler_loop, daemon=True)
    _schedule_thread.start()
    log_message(f"Scheduler uruchomiony", level="system")


def stop_scheduler():
    global schedule_running
    schedule_running = False
    schedule.clear()
    log_message(f"Scheduler zatrzymany", level="system")

def start_scheduler_solo():
    conf = load_conf()

    schedule.every(conf["interwal"]).minutes.do(skanuj_siec)
    schedule.every().day.at(conf["godzina_raportu"]).do(skanuj_siec)
    schedule.every().day.at(conf["godzina_raportu"]).do(generuj_raport_pdf)

    log_message(f"Scheduler uruchomiony", level="system")

    while True:
        schedule.run_pending()
        time.sleep(1)

###--- MIEJSCE NA TESTY ---###
if __name__ == "__main__":
    skanuj_siec()
    generuj_raport_pdf()