import time
from eth_account import Account
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from web3 import Web3

console = Console()
RPC_URL = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

console.print(f"[cyan]Starting brute-force with weak entropy...[/cyan]")

def generate_and_check(max_tries=100000):
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Brute-forcing keys", total=max_tries)
        for i in range(max_tries):
            acct = Account.create()
            addr = acct.address
            balance = w3.eth.get_balance(addr)
            if balance > 0:
                console.log(f"[green]Hit![/green] {addr} balance={w3.fromWei(balance,'ether')} ETH")
                return addr
            progress.update(task, advance=1)
        console.print("[red]No funds found in tested addresses.[/red]")

if __name__ == '__main__':
    generate_and_check()