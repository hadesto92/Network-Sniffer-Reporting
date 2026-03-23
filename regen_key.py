import os, base64, shutil, time

KEY_FILE = "secret.key"
PREF_SIZE = 32

if os.path.exists(KEY_FILE):
    bak = f"{KEY_FILE}.bak.{int(time.time())}"
    shutil.copy2(KEY_FILE, bak)
    print("Stary secret.key zbackupowany jako: ", bak)

new = os.urandom(PREF_SIZE)
with open(KEY_FILE, "wb") as f:
    f.write(base64.b64encode(new))

print("Wygenerowano nowy klicz i zaisano do secret.key (AES-256).")