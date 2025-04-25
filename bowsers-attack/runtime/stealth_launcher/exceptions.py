import time
import traceback
from enum import IntEnum
import os
import platform

class ErrorCode(IntEnum):
    EVASION = 0x100
    PATCHING = 0x200
    PACKING = 0x300
    STEALER = 0x400
    BEACONING = 0x500
    PERSISTENCE = 0x600
    CLEANUP = 0x700

class StageError(Exception):
    def __init__(self, message: str, stage: str = None, code: ErrorCode = None, original_exc=None):
        super().__init__(message)
        self.stage = stage
        self.timestamp = time.time()
        stack = traceback.format_stack()
        # descarta as últimas 2 entradas (esta função e __init__)
        self.trace = ''.join(stack[:-2])
        self.pid = os.getpid()
        self.host = platform.node()
        self.code = code
        self.__cause__ = original_exc

    def __str__(self):
        base = f"[{self.stage or 'Stage'} Error] {self.args[0]}"
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.timestamp))
        if self.__cause__:
            base += f"\nCaused by: {repr(self.__cause__)}"
        return f"{base} (at {ts})\nTrace:\n{self.trace}"

class EvasionError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="evasion", code=ErrorCode.EVASION, original_exc=original_exc)

class PatchError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="patching", code=ErrorCode.PATCHING, original_exc=original_exc)

class PackingError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="payload_packaging", code=ErrorCode.PACKING, original_exc=original_exc)

class StealerError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="stealers_execution", code=ErrorCode.STEALER, original_exc=original_exc)

class BeaconingError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="beaconing", code=ErrorCode.BEACONING, original_exc=original_exc)

class PersistenceError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="persistence", code=ErrorCode.PERSISTENCE, original_exc=original_exc)

class CleanupError(StageError):
    def __init__(self, message: str, original_exc=None):
        super().__init__(message, stage="cleanup", code=ErrorCode.CLEANUP, original_exc=original_exc)