#!/usr/bin/env python3
"""
stealth_launcher.advanced.evasion_techniques
Técnicas de evasão de hypervisores, sandboxes, VMs e containers.
"""

import logging
import ctypes
from ctypes import windll, c_void_p
from stealth_launcher.exceptions import StageError

# --- Low-Level Primitives -----------------------------------

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000

def cpuid_inline():
    """Executa CPUID diretamente em memória."""
    code = bytearray([
        0xB8, 0x00, 0x00, 0x00, 0x40,  # mov eax, 0x40000000
        0x0F, 0xA2,                    # cpuid
        0xC3                           # ret
    ])
    addr = windll.kernel32.VirtualAlloc(
        None,
        ctypes.c_size_t(len(code)),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    if not addr:
        raise StageError(f"VirtualAlloc falhou: {ctypes.GetLastError()}")
    ctypes.memmove(c_void_p(addr), code, len(code))
    func = ctypes.CFUNCTYPE(ctypes.c_int)(addr)
    return func()

def disk_timing():
    """Mede latência de acesso a \\.\PhysicalDrive0 (stub)."""
    # TODO: implementar corretamente com CreateFileW + QueryPerformanceCounter
    pass

def exception_handler(exception_info):
    """Handler para filtrar STATUS_BREAKPOINT."""
    if exception_info.ExceptionRecord.ExceptionCode == 0x80000003:
        return windll.kernel32.EXCEPTION_CONTINUE_EXECUTION
    return windll.kernel32.EXCEPTION_CONTINUE_SEARCH

# --- High-Level Checks --------------------------------------
def cpuid_hypervisor_check() -> bool:
    """Executa CPUID e verifica se está rodando sob hypervisor (bit 31 ECX)."""
    import ctypes
    from ctypes import c_uint, c_size_t, c_void_p, POINTER, windll

    class CPUID_OUT(ctypes.Structure):
        _fields_ = [
            ("eax", c_uint),
            ("ebx", c_uint),
            ("ecx", c_uint),
            ("edx", c_uint)
        ]

    MEM_COMMIT = 0x1000
    PAGE_EXECUTE_READWRITE = 0x40

    # Aloca memória para a shellcode
    cpuid_ptr = windll.kernel32.VirtualAlloc(
        None,
        c_size_t(4096),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    if not cpuid_ptr:
        raise OSError("VirtualAlloc falhou")

    # Shellcode CPUID (modo 64 bits)
    shellcode = bytearray([
        0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
        0x0F, 0xA2,                   # cpuid
        0x89, 0x01,                   # mov [rcx], eax
        0x89, 0x59, 0x04,             # mov [rcx+4], ebx
        0x89, 0x49, 0x08,             # mov [rcx+8], ecx
        0x89, 0x51, 0x0C,             # mov [rcx+12], edx
        0xC3                          # ret
    ])
    ctypes.memmove(cpuid_ptr, shellcode, len(shellcode))

    # Define função com assinatura correta
    FUNC = ctypes.CFUNCTYPE(None, POINTER(CPUID_OUT))
    cpuid_func = FUNC(cpuid_ptr)

    # Executa a shellcode
    output = CPUID_OUT()
    cpuid_func(ctypes.byref(output))

    # Libera a memória
    windll.kernel32.VirtualFree(cpuid_ptr, 0, 0x8000)

    # Verifica o bit 31 de ECX
    return bool(output.ecx & (1 << 31))


def anti_hypervisor() -> bool:
    """Detecta se estamos rodando sob hypervisor com máxima resiliência."""
    try:
        if cpuid_hypervisor_check():
            logging.warning("[Evasion] Hypervisor detectado via CPUID!")
            return False

        try:
            disk_timing()  # futuro: latência física real do disco
        except NotImplementedError:
            logging.debug("[Evasion] disk_timing() ainda não implementado")
        except Exception as dt_err:
            logging.warning(f"[Evasion] Falha leve em disk_timing: {dt_err}")

    except Exception as e:
        logging.error(f"[Evasion] anti_hypervisor falhou: {e}")
        return False

    return True

def detect_sandbox():
    """Teste simples para sandbox (stub)."""
    # TODO: implementar via DNS-over-HTTPS
    return True

def detect_vm():
    """Detecta ambiente virtualizado via GPU timing (stub)."""
    # TODO: implementar via tempo de resposta da GPU
    return True

def detect_hypervisor_timing_gpu():
    """Mede tempo de renderização GPU para detectar hypervisor (stub)."""
    # TODO: implementar método real
    return True

def fingerprint_hardware_unique():
    """Coleta um fingerprint único do hardware (stub)."""
    # TODO: implementar fingerprinting de hardware
    return True

def evasion_container():
    """Detecta execução em container (Docker/WSL) (stub)."""
    # TODO: implementar verificação de ambiente containerizado
    return True

# --- Orchestration Entrypoint -------------------------------

def run_evasion(cfg):
    """Executa todas as técnicas de evasão."""
    logging.info("=== Stage: evasion ===")

    # 1. Anti-debug / hypervisor (falha crítica)
    if not anti_hypervisor():
        raise StageError("Detecção de hypervisor/anti-debug falhou")

    # 2. Testes não-críticos
    if not detect_sandbox():
        logging.warning("Sandbox detectada, continua execução")
    if not detect_vm():
        logging.warning("VM detectada, continua execução")

    # 3. Checks adicionais (não-críticos)
    detect_hypervisor_timing_gpu()
    fingerprint_hardware_unique()
    evasion_container()

    logging.info("=== Evasion concluído ===")
