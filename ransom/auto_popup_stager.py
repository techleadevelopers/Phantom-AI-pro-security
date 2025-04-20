import webbrowser
import os
import sys
import time

def auto_invoke_popup(html_path: str):
    try:
        # Corrige path no Windows
        html_path = os.path.abspath(html_path)
        if not os.path.exists(html_path):
            print(f"[❌] Caminho da nota HTML inválido: {html_path}")
            return

        # Aguarda 2s antes de abrir (opcional)
        time.sleep(2)

        # Abre no navegador padrão do sistema
        webbrowser.open(f"file:///{html_path}")
        print(f"[🔔] Popup Defender Fake invocado com UID: {html_path}")
    except Exception as e:
        print(f"[❌] Falha ao abrir o HTML no navegador: {e}")
