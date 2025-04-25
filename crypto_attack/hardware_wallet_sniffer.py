# File: crypto_threats/hardware_wallet_sniffer.py
import sys
from rich.console import Console
from rich.table import Table

console = Console()

try:
    import usb.core
    import usb.util
except ImportError:
    console.print("[red]Erro: dependência 'pyusb' não encontrada. Instale com `pip install pyusb`[/red]")
    sys.exit(1)

# A partir daqui, você sabe que usb.core e usb.util existem
devices = usb.core.find(find_all=True)

console.print("[bold magenta]Dispositivos USB conectados:[/bold magenta]")
table = Table("Vendor ID", "Product ID", "Manufacturer", "Product")
for dev in devices:
    try:
        manu = usb.util.get_string(dev, dev.iManufacturer)
        prod = usb.util.get_string(dev, dev.iProduct)
    except Exception:
        manu = prod = "Unknown"
    table.add_row(hex(dev.idVendor), hex(dev.idProduct), manu, prod)
console.print(table)
