# File: crypto_threats/subdomain_takeover.py
import dns.resolver
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

console = Console()
DOMAINS = ['example.com', 'test.com']

def check_subdomains(domains):
    with Progress(TextColumn("Scanning {task.description}"), BarColumn(), console=console) as prog:
        task = prog.add_task("subdomain", total=len(domains))
        for d in domains:
            sub = f"www.{d}"
            try:
                answers = dns.resolver.resolve(sub, 'CNAME')
                console.log(f"[red]CNAME found for {sub}: {answers[0]}[/red]")
                r = requests.get(f"http://{sub}")
                if r.status_code==404:
                    console.log(f"[green]Potential takeover at {sub}[/green]")
            except Exception:
                pass
            prog.update(task, advance=1)

if __name__=='__main__':
    check_subdomains(DOMAINS)
