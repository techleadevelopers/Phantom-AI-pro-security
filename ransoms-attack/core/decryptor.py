# File: core/decryptor.py
import os
import sys
import json
from datetime import datetime, timezone
from hashlib import sha256

# Ajusta sys.path para importar pacotes do projeto
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Import local do fake defender
from ransom.fullscreen_fake_defender import trigger_defender_alert  # 🔥 Integração BRUTAL

# Inicializa console Rich
console = Console()
MAGIC_BYTES = b'LOCKED_RANSOMLAB'


def decrypt_file(encrypted_path: str, private_key_path: str, uid: str) -> None:
    console.clear()
    console.print(Panel(f"[bold red]Decrypting[/bold red] {os.path.basename(encrypted_path)}", title="Decryptor BRUTAL", border_style="red"))

    # Validações iniciais
    if not os.path.isfile(encrypted_path):
        console.print(f"[red]Arquivo não encontrado:[/red] {encrypted_path}")
        return
    if not os.path.isfile(private_key_path):
        console.print(f"[red]Chave privada não encontrada:[/red] {private_key_path}")
        return

    try:
        # Leitura e verificação de magic bytes
        with open(encrypted_path, 'rb') as f:
            header = f.read(len(MAGIC_BYTES) + 2)
        magic = header[:len(MAGIC_BYTES)]
        if magic != MAGIC_BYTES:
            console.print("[red]Magic bytes inválidos. Não é um arquivo LOCKED_RANSOMLAB válido.[/red]")
            return
        key_size = int.from_bytes(header[len(MAGIC_BYTES):], 'big')
        with open(encrypted_path, 'rb') as f:
            f.seek(len(MAGIC_BYTES) + 2)
            rest = f.read()

        # Carrega chave RSA
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
            task = prog.add_task("Loading RSA key", total=None)
            with open(private_key_path, 'rb') as kf:
                private_key = RSA.import_key(kf.read())
            prog.update(task, description="RSA key loaded")
            prog.stop_task(task)

        rsa_encrypted_key = rest[:key_size]
        iv = rest[key_size:key_size+16]
        ciphertext = rest[key_size+16:]

        # Decrypt AES key via RSA
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
            task = prog.add_task("Decrypting AES key", total=None)
            cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
            aes_key = cipher_rsa.decrypt(rsa_encrypted_key)
            prog.update(task, description="AES key decrypted")
            prog.stop_task(task)

        # Decrypt conteúdo AES
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("Decrypting file", total=len(ciphertext))
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext_padded = cipher_aes.decrypt(ciphertext)
            prog.update(task, advance=len(ciphertext))

        # Remove padding
        padding_len = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_len]

                # Exibe conteúdo puro se texto
        decoded = None
        try:
            decoded = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            try:
                decoded = plaintext.decode('cp1252')
            except UnicodeDecodeError:
                # Fallback para latin1 garante visualização de todos bytes
                decoded = plaintext.decode('latin1')
        # Mostra raw text, mesmo que contenha caracteres especiais
        console.print(Panel(decoded, title="📄 Decrypted Content", border_style="white"))

        # Informações do arquivo restaurado
        recovered_hash = sha256(plaintext).hexdigest()
        output_file = encrypted_path.replace('.locked', '')
        file_size = len(plaintext)
        console.print(Panel(f"📁 [bold]File Path:[/bold] {output_file}\n📦 [bold]Size:[/bold] {file_size} bytes", title="File Info", border_style="yellow"))

        # Salva arquivo restaurado
        with open(output_file, 'wb') as outf:
            outf.write(plaintext)

        # Log JSON
        log_data = {
            "uid": uid,
            "original_file": output_file,
            "recovered_from": encrypted_path,
            "sha256": recovered_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        log_file = os.path.join(ROOT, f"log_recover_{uid}.json")
        with open(log_file, 'w', encoding='utf-8') as lf:
            json.dump(log_data, lf, indent=4)

        # Exibe sucesso e tabela de log
        console.print(Panel("[green]✔ Decryption Success![/green]", border_style="green"))
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Field")
        table.add_column("Value", overflow="fold")
        for k, v in log_data.items():
            table.add_row(k, str(v))
        console.print(table)

        # Alerta fake defender
        trigger_defender_alert(uid=uid)

    except Exception as e:
        console.print(Panel(f"[red]Erro inesperado:[/red]\n{e}", border_style="red"))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        console.print("[yellow]Uso:[/yellow] python core/decryptor.py <arquivo.locked> <private.pem> <UID>")
        sys.exit(1)
    _, enc_path, priv_path, uid = sys.argv
    decrypt_file(enc_path, priv_path, uid)
