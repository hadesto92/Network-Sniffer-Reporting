import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "secret.key"   # plik z kluczem AES
KEY_LEN = 32              # 32 bajty = 256 bitów
NONCE_LEN = 12            # rekomendowane dla AESGCM

# -------------------------
# obsługa klucza
# -------------------------
def _ensure_key() -> bytes:
    """Ładuje klucz z pliku albo tworzy nowy, jeśli go nie ma."""
    if not os.path.exists(KEY_FILE):
        key = os.urandom(KEY_LEN)
        with open(KEY_FILE, "wb") as f:
            f.write(base64.b64encode(key))
        return key
    else:
        raw = open(KEY_FILE, "rb").read()
        key = base64.b64decode(raw)
        if len(key) not in (16, 24, 32):
            raise ValueError("Invalid key size in secret.key")
        return key

# -------------------------
# szyfrowanie / odszyfrowanie bajtów
# -------------------------
def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext+tag
    return base64.b64encode(nonce + ct)

def decrypt_bytes(b64data: bytes, key: bytes) -> bytes:
    raw = base64.b64decode(b64data)
    nonce = raw[:NONCE_LEN]
    ct = raw[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# -------------------------
# operacje na plikach JSON
# -------------------------
def write_encrypted_json(path: str, obj):
    """Zapisuje obiekt JSON zaszyfrowany AES-GCM."""
    key = _ensure_key()
    plaintext = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    enc = encrypt_bytes(plaintext, key)
    with open(path, "wb") as f:
        f.write(enc)

def read_encrypted_json(path: str):
    """Czyta plik JSON zaszyfrowany AES-GCM i zwraca obiekt Python."""
    key = _ensure_key()
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        data = f.read()
    plaintext = decrypt_bytes(data, key)
    return json.loads(plaintext.decode("utf-8"))