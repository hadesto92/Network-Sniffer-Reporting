import base64, os, sys

KEY_FILE= "secret.key"
if not os.path.exists(KEY_FILE):
    print("Brak pliku secret.key (to normalne przy pierwszym uruchomieniu).")
    sys.exit(0)
raw = open(KEY_FILE, "rb").read().strip()
print("Rozmiar pliku (bajtów):", len(raw))
try:
    dec = base64.b64decode(raw, validate=True)
    print("Base64 decode -> ", len(dec), " bajtów")
except Exception as e:
    print("Base64 decode nie powiódł się: ", e)

try:
    txt = raw.decode('utf-8', errors='ignore').strip()
    if all(c in "0123456789abcdefABCDEF" for c in txt) and len(txt) % 2 == 0:
        print("Wygląda jak hex-string. Długość po hex-dekodzie: ", len(bytes.fromhex(txt)))
    else:
        print("Nie wygląda to jak hex-string.")
except Exception:
    pass

print("Zgodne długości AES: 16, 24 lub 32 bajty")
