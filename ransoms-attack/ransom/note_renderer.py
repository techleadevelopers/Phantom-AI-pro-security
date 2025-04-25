import os
import webbrowser

def render_ransom_note(path: str):
    if not os.path.exists(path):
        print(f"[❌] Nota não encontrada: {path}")
        return
    webbrowser.open(f"file://{os.path.abspath(path)}")
