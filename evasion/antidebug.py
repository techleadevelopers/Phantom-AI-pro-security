import sys
import os
import ctypes
import psutil
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from typing import List

def check_sys_gettrace() -> bool:
    return sys.gettrace() is not None

def check_debugger_processes() -> List[str]:
    suspicious = []
    known_debuggers = [
        "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ollydbg.exe", "wireshark.exe", "fiddler.exe",
        "procmon.exe", "procexp.exe", "reshacker.exe",
        "ImmunityDebugger.exe", "dnSpy.exe", "debugger.exe"
    ]
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'].lower() in known_debuggers:
                suspicious.append(proc.info['name'])
        except Exception:
            continue
    return suspicious

def check_winapi_flags() -> bool:
    kernel32 = ctypes.windll.kernel32
    if kernel32.IsDebuggerPresent():
        return True
    is_debugged = ctypes.c_int(0)
    kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debugged))
    return bool(is_debugged.value)

def check_peb_being_debugged() -> bool:
    class PEB(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_byte * 2),
            ("BeingDebugged", ctypes.c_byte),
            ("Reserved2", ctypes.c_byte),
        ]

    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.POINTER(PEB)),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_void_p),
            ("Reserved3", ctypes.c_void_p)
        ]

    NtQueryInformationProcess = ctypes.windll.ntdll.NtQueryInformationProcess
    pbi = PROCESS_BASIC_INFORMATION()
    ret_length = ctypes.c_ulong()
    status = NtQueryInformationProcess(
        ctypes.windll.kernel32.GetCurrentProcess(),
        0,
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(ret_length)
    )
    if status == 0:
        peb = pbi.PebBaseAddress.contents
        return bool(peb.BeingDebugged)
    return False

def run_antidebug(verbose=True):
    alerts = []

    if check_sys_gettrace():
        alerts.append("🧠 sys.gettrace() ativado")

    found = check_debugger_processes()
    if found:
        alerts.append(f"🛑 Debuggers detectados: {', '.join(found)}")

    if check_winapi_flags():
        alerts.append("🪛 WinAPI IsDebuggerPresent / RemoteDebugger")

    if check_peb_being_debugged():
        alerts.append("⚠️ NTGlobalFlags via PEB => Debugger ativo")

    if verbose:
        if alerts:
            print("\n🚨 [ANTIDEBUG] AMEAÇA DETECTADA:")
            for a in alerts:
                print(f"  └── {a}")
        else:
            print("✅ [ANTIDEBUG] Nenhum depurador ativo detectado.")

    return alerts

if __name__ == "__main__":
    run_antidebug()
