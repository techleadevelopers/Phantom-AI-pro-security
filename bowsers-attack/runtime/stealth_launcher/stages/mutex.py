import os
import tempfile
import logging
import errno
from pathlib import Path
from ctypes import wintypes, windll, byref, c_void_p, get_last_error
from contextlib import contextmanager
from stealth_launcher.exceptions import StageError
from stealth_launcher.advanced.syscall_stubs import (
    create_mutex_nt,
    create_event_nt,
    create_semaphore_nt,
    create_section_nt,
    global_add_atom_nt,
    create_named_pipe_nt,
    close_handle_nt,
)

# Constants
ERROR_ALREADY_EXISTS = 183
INVALID_HANDLE_VALUE = c_void_p(-1).value

# Configurar protótipos de API
kernel32 = windll.kernel32
kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype  = wintypes.HANDLE
kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype  = wintypes.HANDLE
kernel32.CreateSemaphoreW.argtypes = [wintypes.LPVOID, wintypes.LONG, wintypes.LONG, wintypes.LPCWSTR]
kernel32.CreateSemaphoreW.restype  = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype  = wintypes.BOOL

class MultiTechniqueMutex:
    """
    Enforce single-instance using multiple stealth techniques:
     1) Win32 CreateMutexW
     2) Direct syscall CreateMutex
     3) Win32 CreateEventW
     4) Direct syscall CreateEvent
     5) Win32 CreateSemaphoreW
     6) Direct syscall CreateSemaphore
     7) Direct syscall CreateSection
     8) GlobalAddAtom via syscall
     9) Named Pipe via syscall
    10) File lock fallback

    Usage:
        with MultiTechniqueMutex("MyApp") as m:
            # se não houver exceção, instância única garantida
            ...
    """

    def __init__(self, name: str):
        """
        Args:
            name: base name (shared) entre instâncias para detecção.
        """
        self.name = name
        self._handles: list[tuple[str, int]] = []
        self._lockfile: Path | None = None

    def _try_win32(self, func, *args) -> bool:
        """Tenta criar objeto Win32 e checar erro ALREADY_EXISTS."""
        h = func(*args)
        if not h:
            return False
        last = get_last_error()
        if last == ERROR_ALREADY_EXISTS:
            # objeto já existia
            kernel32.CloseHandle(h)
            return False
        self._handles.append(("win32", h))
        return True

    def _try_syscall(self, stub, name: str) -> bool:
        """Tenta criar objeto via syscall stub; trata INVALID_HANDLE."""
        try:
            h = stub(name)
            if h and h != INVALID_HANDLE_VALUE:
                self._handles.append(("syscall", h))
                return True
        except Exception:
            pass
        return False

    def acquire(self) -> None:
        """Tenta todas as técnicas em ordem. Lança StageError se duplicado."""
        # 1. Win32 Mutex
        if self._try_win32(kernel32.CreateMutexW, None, False, self.name):
            return

        # 2. Syscall Mutex
        if self._try_syscall(create_mutex_nt, self.name):
            return

        # 3. Win32 Event
        if self._try_win32(kernel32.CreateEventW, None, False, False, self.name):
            return

        # 4. Syscall Event
        if self._try_syscall(create_event_nt, self.name):
            return

        # 5. Win32 Semaphore
        if self._try_win32(kernel32.CreateSemaphoreW, None, 1, 1, self.name):
            return

        # 6. Syscall Semaphore
        if self._try_syscall(create_semaphore_nt, self.name):
            return

        # 7. Syscall Section (file mapping)
        if self._try_syscall(create_section_nt, self.name):
            return

        # 8. Syscall GlobalAddAtom
        if self._try_syscall(global_add_atom_nt, self.name):
            return

        # 9. Named Pipe via syscall
        pipe_name = rf"\\.\pipe\{self.name}"
        if self._try_syscall(create_named_pipe_nt, pipe_name):
            return

        # 10. File lock
        lockfile = Path(tempfile.gettempdir()) / f"{self.name}.lock"
        try:
            fd = os.open(str(lockfile), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            self._handles.append(("file", fd))
            self._lockfile = lockfile
            return
        except FileExistsError:
            raise StageError(f"Instância duplicada detectada via file lock: {lockfile}")
        except OSError as e:
            raise StageError(f"Erro criando lock file: {e}")

        # Se chegou aqui, falhou em tudo
        raise StageError(f"Outra instância detectada (mutex name={self.name})")

    def release(self) -> None:
        """Fecha todos os handles e remove arquivo de lock se houver."""
        for kind, h in self._handles:
            try:
                if kind == "win32":
                    kernel32.CloseHandle(h)
                elif kind == "syscall":
                    close_handle_nt(h)
                elif kind == "file":
                    os.close(h)
                    if self._lockfile and self._lockfile.exists():
                        self._lockfile.unlink()
            except Exception:
                logging.debug(f"Falha ao liberar handle {kind}: {h}", exc_info=True)
        self._handles.clear()

    def __enter__(self) -> "MultiTechniqueMutex":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def acquire_mutex(name: str) -> MultiTechniqueMutex:
    """
    Convenience wrapper. Lança StageError se duplicado.
    """
    m = MultiTechniqueMutex(name)
    m.acquire()
    return m


def release_mutex(m: MultiTechniqueMutex) -> None:
    """
    Convenience wrapper para liberar mutex.
    """
    m.release()