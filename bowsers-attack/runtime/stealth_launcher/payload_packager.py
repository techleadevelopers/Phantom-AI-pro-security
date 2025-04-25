import shutil
import tempfile
import logging
from pathlib import Path
from stealth_launcher.exceptions import PackingError

def pack_payload(input_path: str, obfuscation: bool = False) -> str:
    """
    Empacota (e opcionalmente ofusca) o payload.

    Args:
        input_path: caminho para o executável original.
        obfuscation: se True, aplica uma ofuscação simples.

    Returns:
        O caminho para o arquivo empacotado pronto para injeção.

    Raises:
        PackingError em caso de falha de I/O.
    """
    try:
        src = Path(input_path)
        if not src.is_file():
            raise PackingError(f"Payload não encontrado em {input_path}")

        # Cria um nome no temp
        dst = Path(tempfile.gettempdir()) / (src.stem + "_packed" + src.suffix)

        # Copia o binário
        shutil.copy2(src, dst)

        if obfuscation:
            # Exemplo de ofuscação trivial: XOR de cada byte com 0xAA
            data = dst.read_bytes()
            obf = bytes(b ^ 0xAA for b in data)
            dst.write_bytes(obf)
            logging.info(f"[PayloadPackager] Ofuscação aplicada em {dst}")

        logging.info(f"[PayloadPackager] Payload empacotado em {dst}")
        return str(dst)
    except Exception as e:
        raise PackingError(f"Erro ao empacotar payload: {e}")
