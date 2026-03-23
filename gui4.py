import os
import json
import tkinter as tk

from tkinter import filedialog, messagebox, scrolledtext, ttk
from main import save_conf, load_conf, start_scheduler, stop_scheduler, start_scheduler_solo, generuj_raport_pdf, \
    LOG_FILE, ARCHIWUM_FILE, wczytaj_archiwum


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer Reporting")
        self.conf = load_conf()

        ###--- POLA USTAWIEŃ ---###
        tk.Label(root, text="Adres sieci (CIDR):").grid(row=0, column=0, sticky="w")
        self.entry_siec = tk.Entry(root, width=30)
        self.entry_siec.grid(row=0, column=1)
        self.entry_siec.insert(0, self.conf["siec"])

        tk.Label(root, text="Interwał (minuty):").grid(row=1, column=0, sticky="w")
        self.entry_interwal = tk.Entry(root, width=30)
        self.entry_interwal.grid(row=1, column=1)
        self.entry_interwal.insert(0, self.conf["interwal"])

        tk.Label(root, text="Godzina raportu (HH:MM):").grid(row=2, column=0, sticky="w")
        self.entry_godzina = tk.Entry(root, width=30)
        self.entry_godzina.grid(row=2, column=1)
        self.entry_godzina.insert(0, self.conf["godzina_raportu"])

        tk.Label(root, text="Katalog dla raportów:").grid(row=3, column=0, sticky="w")
        self.entry_raport_dir = tk.Entry(root, width=30)
        self.entry_raport_dir.grid(row=3, column=1)
        self.entry_raport_dir.insert(0, self.conf["raport_dir"])
        tk.Button(root, text="...", command=self.choose_raport_dir).grid(row=3, column=2, pady=2, sticky="we")

        tk.Label(root, text="Ścieżka do nmap.exe:").grid(row=4, column=0, sticky="w")
        self.entry_nmap = tk.Entry(root, width=30)
        self.entry_nmap.grid(row=4, column=1)
        self.entry_nmap.insert(0, self.conf["nmap_path"])
        tk.Button(root, text="...", command=self.choose_nmap_path).grid(row=4, column=2, pady=2, sticky="we")

        tk.Label(root, text="Adres e-mail:").grid(row=5, column=0, sticky="w")
        self.entry_email = tk.Entry(root, width=30)
        self.entry_email.grid(row=5, column=1)
        self.entry_email.insert(0, self.conf["recipient_email"])
        tk.Button(root, text="Ustawienia email", command=self.setting_email).grid(row=5, column=2, pady=2, sticky="we")

        ###--- PRZYCISKI ---###
        self.btn_start = tk.Button(root, text="Start", bg="green", fg="white", font=("Arial", 16, "bold"), command=self.toggle_scheduler)
        self.btn_start.grid(row=6, column=0, columnspan=3, pady=15)

        tk.Button(root, text="Wymuś raport", command=lambda: generuj_raport_pdf(z_wym_raport=True)).grid(row=7, column=0, pady=5)
        tk.Button(root, text="Zapisz ustawienia", command=self.save_settings).grid(row=7, column=1, pady=5)
        tk.Button(root, text="Pokaż archiwum", command=self.show_archive).grid(row=7, column=2, pady=5)
        tk.Button(root, text="Otwórz folder raportów", command=self.open_raport_dir).grid(row=8, column=0, pady=5)
        tk.Button(root, text="Przywróć ustawienia domyślne", command=self.load_defaults).grid(row=8, column=1, pady=5)
        tk.Button(root, text="Pokaż logi", command=self.show_logs).grid(row=8, column=2, pady=5)
        tk.Button(root, text="Edytuj dane", command=self.edit_host).grid(row=9, column=2, pady=5)

        ###--- PRZYCISK POMOCY ---###
        tk.Button(root, text="[?]", command=self.show_help).grid(row=0, column=3, rowspan=2, padx=10)

    ###--- FUNKCJE GUI ---###
    def edit_host(self):
        date = wczytaj_archiwum()

        win_edit_host = tk.Toplevel(self.root)
        win_edit_host.title("Edytowanie danych hostów")
        win_edit_host.geometry("400x200")

        frame_edit_host = tk.Frame(win_edit_host)
        frame_edit_host.pack(fill="x")

        list_key = list(date.keys())

        tk.Label(frame_edit_host, text="Wybierz hosta:").grid(row=1, column=0, sticky="w")
        combo = ttk.Combobox(frame_edit_host, values=list_key, width=27)
        combo.grid(row=1, column=1)
        combo.current(0)

        tk.Label(frame_edit_host, text="Wpisz nazwę hosta:").grid(row=2, column=0, sticky="w")
        self.entry_edited_host_name = tk.Entry(frame_edit_host, width=30)
        self.entry_edited_host_name.grid(row=2, column=1)
        self.entry_edited_host_name.insert(0, combo.get())

        tk.Label(frame_edit_host, text="Pierwszy raz widziany:").grid(row=3, column=0, sticky="w")
        self.label_first_seen = tk.Label(frame_edit_host, text="-")
        self.label_first_seen.grid(row=3, column=1, sticky="w")
        tk.Label(frame_edit_host, text="OStatni raz widziany: ").grid(row=4, column=0, sticky="w")
        self.label_last_seen = tk.Label(frame_edit_host, text="-")
        self.label_last_seen.grid(row=4, column=1, sticky="w")

        def load_data(event=None):
            host = combo.get()
            dane = date.get(host, {})

            self.entry_edited_host_name.delete(0, tk.END)
            self.entry_edited_host_name.insert(0, dane.get("name_host", ""))

            self.label_first_seen.config(text=dane.get("first_seen","-"))
            self.label_last_seen.config(text=dane.get("last_seen", "-"))

        combo.bind("<<ComboboxSelected>>", load_data)
        load_data()

        tk.Button(frame_edit_host, text="Zapisz", command=lambda: self.save_edit_host()).grid(row=5, column=0)
        tk.Button(frame_edit_host, text="Pokaż listę IP", command=lambda: self.show_ip_list(date.get(combo.get(), {}).get("ips"), combo.get())).grid(row=5, column=1)

    def show_ip_list(self, ip_list, host):
        win_ip_host = tk.Toplevel(self.root)
        win_ip_host.title(f"Lista adresów IP hosta {host}")
        win_ip_host.geometry("200x100")

        frame_ip_host = tk.Frame(win_ip_host)
        frame_ip_host.pack(fill="x")

        txt = scrolledtext.ScrolledText(frame_ip_host, width=100, height=30)
        txt.pack()
        txt.insert(tk.END, json.dumps(ip_list, indent=4, ensure_ascii=False))

    def save_edit_host(self):
        return

    def setting_email(self):
        self.conf = load_conf()

        win_email = tk.Toplevel(self.root)
        win_email.title("Ustawienia e-mail")
        win_email.geometry("450x100")

        frame_email = tk.Frame(win_email)
        frame_email.pack(fill="x")

        label = tk.Label(frame_email, text=f"Podaj e-mail i hasło bezpieczeństwa aplikacji google", font=("Arial", 14))
        label.grid(row=0, column=0, columnspan=3)

        tk.Label(frame_email, text="Adres e-mail:").grid(row=1, column=0, sticky="w")
        self.entry_sender_email = tk.Entry(frame_email, width=30)
        self.entry_sender_email.grid(row=1, column=1)
        self.entry_sender_email.insert(0, self.conf["sender_email"])

        tk.Label(frame_email, text="Hasło bezpieczeństwa:").grid(row=2, column=0, sticky="w")
        self.entry_sender_password = tk.Entry(frame_email, width=30)
        self.entry_sender_password.grid(row=2, column=1)
        self.entry_sender_password.insert(0, self.conf["sender_password"])

        tk.Button(frame_email, text="Zapisz", command=lambda: save_email()).grid(row=4, column=1)

        def save_email():
            self.conf["sender_email"] = self.entry_sender_email.get()
            self.conf["sender_password"] = self.entry_sender_password.get()

            save_conf(self.conf)
            win_email.destroy()

    def choose_nmap_path(self):
        path = filedialog.askopenfilename(title="Wybierz plik nmap")
        if path:
            self.entry_nmap.delete(0, tk.END)
            self.entry_nmap.insert(0, path)

    def choose_raport_dir(self):
        folder = filedialog.askdirectory(title="Wybierz folder do raportów")
        if folder:
            self.entry_raport_dir.delete(0, tk.END)
            self.entry_raport_dir.insert(0, folder)

    def toggle_scheduler(self):
        #start_scheduler_solo()
        from main import schedule_running
        if not schedule_running:
            self.start_save_settings()
            start_scheduler()
            self.btn_start.config(text="Stop", bg="red")
        else:
            stop_scheduler()
            self.btn_start.config(text="Start", bg="green")

    def select_raport_dir(self):
        dirname = filedialog.askdirectory()
        if dirname:
            self.entry_raport_dir.delete(0, tk.END)
            self.entry_raport_dir.insert(0, dirname)

    def select_nmap_path(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.entry_nmap.delete(0, tk.END)
            self.entry_nmap.insert(0, filename)

    def save_settings(self):
        self.conf["siec"] = self.entry_siec.get()
        self.conf["interwal"] = int(self.entry_interwal.get())
        self.conf["godzina_raportu"] = self.entry_godzina.get()
        self.conf["raport_dir"] = self.entry_raport_dir.get()
        self.conf["nmap_path"] = self.entry_nmap.get()
        self.conf["recipient_email"] = self.entry_email.get()
        save_conf(self.conf)
        messagebox.showinfo(f"Ustawienia", f"Ustawienia zotały zapisane.")

    def start_save_settings(self):
        self.conf["siec"] = self.entry_siec.get()
        self.conf["interwal"] = int(self.entry_interwal.get())
        self.conf["godzina_raportu"] = self.entry_godzina.get()
        self.conf["raport_dir"] = self.entry_raport_dir.get()
        self.conf["nmap_path"] = self.entry_nmap.get()
        self.conf["recipient_email"] = self.entry_email.get()
        save_conf(self.conf)

    def load_defaults(self):
        if os.path.exists("def_conf.json"):
            with (open("def_conf.json", "r", encoding="utf-8") as f):
                self.conf = json.load(f)
            print(self.conf)
        else:
            self.conf = load_conf()
        print(self.conf)

        self.entry_nmap.delete(0, tk.END)
        self.entry_nmap.insert(0, self.conf["nmap_path"])
        self.entry_siec.delete(0, tk.END)
        self.entry_siec.insert(0, self.conf["siec"])
        self.entry_godzina.delete(0, tk.END)
        self.entry_godzina.insert(0, self.conf["godzina_raportu"])
        self.entry_interwal.delete(0, tk.END)
        self.entry_interwal.insert(0, self.conf["interwal"])
        self.entry_raport_dir.delete(0, tk.END)
        self.entry_raport_dir.insert(0, self.conf["raport_dir"])
        self.entry_email.delete(0, tk.END)
        self.entry_email.insert(0, self.conf["recipient_email"])
        self.entry_sender_email.delete(0, tk.END)
        self.entry_sender_email.insert(0, self.conf["sender_email"])
        self.entry_sender_password.delete(0, tk.END)
        self.entry_sender_password.insert(0, self.conf["sender_password"])

        self.start_save_settings()
        print(self.conf)

        messagebox.showinfo(f"Ustawienia", f"Ustawienia zotały przywrócone do domyślnych.")

    def open_raport_dir(self):
        os.startfile(self.entry_raport_dir.get())

    def show_archive(self):
        data = wczytaj_archiwum()
        win = tk.Toplevel(self.root)
        win.title("Archiwum")

        frame = tk.Frame(win)
        frame.pack(fill="x")

        tk.Button(frame, text="Raport z archiwum", command=lambda: generuj_raport_pdf(z_archiwum=True)).pack(side="left", padx=5 ,pady=5)

        txt = scrolledtext.ScrolledText(win, width=100, height=30)
        txt.pack()
        txt.insert(tk.END, json.dumps(data, indent=4, ensure_ascii=False))

    def show_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo(f"Logi", f"Brak logów do wyświetlenia.")
            return

        win = tk.Toplevel(self.root)
        win.title("Logi")

        filter_var = tk.StringVar(value="all")

        def refresh_logs():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)

            txt.delete("1.0", tk.END)
            for log in logs:
                if filter_var.get() == "system" and log["level"] != "system":
                    continue
                if filter_var.get() == "error" and log["level"] != "error":
                    continue
                color = "black"
                if log["level"] == "error":
                    color = "red"
                txt.insert(tk.END, f"[{log['time']}]{log['message']}\n", color)
            txt.see(tk.END)

            frame.after(10000, refresh_logs)

        def dellete_log():
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f)
            refresh_logs()

        frame = tk.Frame(win)
        frame.pack(fill="x")
        tk.Button(frame, text="Wszystkie", command=lambda: (filter_var.set("all"), refresh_logs())).pack(side="left", padx=5, pady=5)
        tk.Button(frame, text="Systemowe", command=lambda: (filter_var.set("system"), refresh_logs())).pack(side="left", padx=5, pady=5)
        tk.Button(frame, text="Błędy", command=lambda: (filter_var.set("error"), refresh_logs())).pack(side="left", padx=5, pady=5)
        tk.Button(frame, text="Wyczyść logi", command=lambda: dellete_log()).pack(side="right", padx=5, pady=5)

        txt = scrolledtext.ScrolledText(win, width=100, height=30)
        txt.pack()
        txt.tag_config("red", foreground="red")
        txt.see(tk.END)

        refresh_logs()
        frame.after(10000, refresh_logs)

    def show_help(self):
        help_text = (
            "Instrukcja obsługi: \n\n"
            " -> Start/Stop: uruchamia lub zatrzymuje skanwowanie \n"
            " -> Wymuś raport: generuje raport natychmiastowoy \n"
            " -> Raport z archiwum: generuje raport na podstawie wszystkich danyhch historycznych \n"
            " -> Logi: dalej podląd na zdarzenia generowane przez program \n"
            " -> Przywróć ustawienia domyślne: reset do ustawień z def_conf.json \n"
            "\n\n\n"
            "Twórca: Karol 'HADESTO' Lach"
        )
        messagebox.showinfo(f"Pomoc", f"{help_text}")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()