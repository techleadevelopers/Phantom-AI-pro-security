from web3 import Web3
from rich.console import Console
from rich.progress import SpinnerColumn, TextColumn, Progress
from rich.panel import Panel

console = Console()
RPC_URL = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
w3 = Web3(Web3.HTTPProvider(RPC_URL))
PRIVATE_KEY = "0xYourPrivateKey"
CONTRACT_ADDRESS = "0xYourTokenContract"

abi = [...]  # ERC20 ABI snippet
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
account = w3.eth.account.from_key(PRIVATE_KEY)

def send_approval(spender, amount):
    tx = contract.functions.approve(spender, amount).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 100000,
        'gasPrice': w3.toWei('50', 'gwei')
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    console.log(f"[green]Approval tx sent:[/green] {tx_hash.hex()}")

if __name__=='__main__':
    spender = "0xSpenderAddress"
    amount = 2**256-1
    console.print(Panel(f"[bold]Phishing unlimited approval to {spender}[/bold]", border_style="yellow"))
    with Progress(SpinnerColumn(), TextColumn("Sending approval..."), console=console) as prog:
        prog.add_task("approve", total=None)
        send_approval(spender, amount)
    console.print("[bold green]Done[/bold green]")
