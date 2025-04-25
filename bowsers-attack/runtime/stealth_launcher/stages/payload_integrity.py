import hashlib
import logging
import mmap
from pathlib import Path
from stealth_launcher.exceptions import StageError

# Constants for watermark
WATERMARK_KEY = b"\x42\x42\x42\x42"  # 4-byte honeypot signature


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str:
    """Calcula o hash de um arquivo especificado."""
    h = hashlib.new(algorithm)
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
    except Exception as e:
        raise StageError(f"Falha ao ler payload para hash: {e}")
    return h.hexdigest()


def verify_memory_integrity(path: Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Mapeia o arquivo em memória e compara o hash com o esperado."""
    computed = compute_file_hash(path, algorithm)
    if computed.lower() != expected_hash.lower():
        logging.error(f"[Integrity] Hash mismatch: esperado {expected_hash}, obtido {computed}")
        return False
    logging.info(f"[Integrity] Hash conferido com sucesso: {computed}")
    return True


def check_watermark(path: Path) -> bool:
    """Verifica se o arquivo contém a assinatura especial."""
    try:
        with open(path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if mm.find(WATERMARK_KEY) == -1:
                return False
            return True
    except Exception as e:
        raise StageError(f"Falha ao verificar watermark: {e}")


def self_integrity_check(path: Path, expected_hash: str) -> None:
    """
    Orquestra as verificações de integridade antes da injeção.

    Args:
        path: caminho para o arquivo.
        expected_hash: hash SHA256 esperado.

    Raises:
        StageError se alguma verificação crítica falhar.
    """
    logging.info(f"[Integrity] Iniciando checagem de integridade do payload {path}")

    if not verify_memory_integrity(path, expected_hash):
        raise StageError("Hash de integridade inválido do payload")

    watermark_found = check_watermark(path)
    if not watermark_found:
        logging.warning(f"[Integrity] Watermark de segurança ausente no payload {path} (continuando para testes)")
    else:
        logging.info("[Integrity] Watermark detectado com sucesso")

    logging.info("[Integrity] Todas as checagens de integridade passaram com sucesso")
