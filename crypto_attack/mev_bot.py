# File: crypto_threats/mev_bot.py
import time
from web3 import Web3
from rich.console import Console
from rich.progress import Progress, BarColumn, TimeElapsedColumn
from rich.table import Table

console = Console()
RPC_URL = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

console.print(f"[bold cyan]Connected to RPC:[/bold cyan] {RPC_URL}")

ADDRESS_REGEX = r"\b0x[a-fA-F0-9]{40}\b"

processed = set()

def monitor_mempool():
    console.rule("[magenta]MEV Bot Monitoring Mempool[/magenta]")
    with Progress("[progress.description]{task.description}", BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Scanning pending txs...", start=False)
        while True:
            try:
                pending = w3.eth.get_block('pending')['transactions']
                progress.start_task(task)
                for tx in pending:
                    if tx not in processed:
                        processed.add(tx)
                        receipt = w3.eth.get_transaction(tx)
                        to = receipt.get('to')
                        value = w3.fromWei(receipt.get('value', 0), 'ether')
                        console.log(f"[green]Tx→[/green] {tx.hex()} [blue]to[/blue]={to} [yellow]value[/yellow]={value} ETH")
                        # Example front-run simulation: send zero-value call
                progress.stop_task(task)
                time.sleep(5)
            except Exception as e:
                console.log(f"[red]Error fetching mempool:[/red] {e}")
                time.sleep(5)

if __name__ == '__main__':
    monitor_mempool()
