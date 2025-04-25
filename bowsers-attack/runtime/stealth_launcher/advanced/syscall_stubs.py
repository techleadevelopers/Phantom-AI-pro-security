# stealth_launcher/advanced/syscall_stubs.py

import ctypes
from ctypes import wintypes

ntdll    = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32")

def create_mutex_nt(name: str) -> wintypes.HANDLE:
    """
    Stub de NtCreateMutant – ainda não implementado.
    """
    raise NotImplementedError("create_mutex_nt não implementado")

def create_event_nt(name: str) -> wintypes.HANDLE:
    """
    Stub de NtCreateEvent – ainda não implementado.
    """
    raise NotImplementedError("create_event_nt não implementado")

def create_semaphore_nt(name: str) -> wintypes.HANDLE:
    """
    Stub de NtCreateSemaphore – ainda não implementado.
    """
    raise NotImplementedError("create_semaphore_nt não implementado")

def create_section_nt(name: str) -> wintypes.HANDLE:
    """
    Stub de NtCreateSection – ainda não implementado.
    """
    raise NotImplementedError("create_section_nt não implementado")

def global_add_atom_nt(name: str) -> int:
    """
    Stub de NtGlobalAddAtom – ainda não implementado.
    """
    raise NotImplementedError("global_add_atom_nt não implementado")

def create_named_pipe_nt(pipe_name: str) -> wintypes.HANDLE:
    """
    Stub de NtCreateNamedPipeFile – ainda não implementado.
    """
    raise NotImplementedError("create_named_pipe_nt não implementado")

def close_handle_nt(handle: int) -> None:
    """
    Stub de NtClose – ainda não implementado.
    """
    raise NotImplementedError("close_handle_nt não implementado")

def open_process_nt(proc_name: str) -> int:
    """
    Stub de NtOpenProcess/NtCreateProcessEx – ainda não implementado.
    """
    raise NotImplementedError("open_process_nt não implementado")

def nt_map_view_of_section(path: str) -> int:
    """
    Stub de NtCreateSection + NtMapViewOfSection – ainda não implementado.
    """
    raise NotImplementedError("nt_map_view_of_section não implementado")

def nt_unmap_view_of_section(base_address: int) -> None:
    """
    Stub de NtUnmapViewOfSection – ainda não implementado.
    """
    raise NotImplementedError("nt_unmap_view_of_section não implementado")

def write_memory_nt(pid: int, section_handle: int) -> None:
    """
    Stub de NtWriteVirtualMemory – ainda não implementado.
    """
    raise NotImplementedError("write_memory_nt não implementado")

def create_remote_thread_nt(pid: int) -> None:
    """
    Stub de NtCreateThreadEx – ainda não implementado.
    """
    raise NotImplementedError("create_remote_thread_nt não implementado")

def create_process_nt(image_path: str, command_line: str = None) -> int:
    """
    Stub de NtCreateProcessEx – ainda não implementado.
    """
    raise NotImplementedError("create_process_nt não implementado")

def queue_user_apc_nt(apc_routine: int, thread_handle: int, apc_context: int) -> None:
    """
    Stub de NtQueueApcThread – ainda não implementado.
    """
    raise NotImplementedError("queue_user_apc_nt não implementado")

def suspend_thread_nt(thread_handle: int) -> None:
    """
    Stub de NtSuspendThread – ainda não implementado.
    """
    raise NotImplementedError("suspend_thread_nt não implementado")

def resume_thread_nt(thread_handle: int) -> None:
    """
    Stub de NtResumeThread – ainda não implementado.
    """
    raise NotImplementedError("resume_thread_nt não implementado")
