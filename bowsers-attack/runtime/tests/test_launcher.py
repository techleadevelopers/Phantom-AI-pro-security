import pytest
import os
from stealth_launcher import verify_signature, Config, load_config

def test_verify_signature_pass(tmp_path):
    f = tmp_path / "f.bin"
    data = b"test"
    f.write_bytes(data)
    sha = __import__('hashlib').sha256(data).hexdigest()
    assert verify_signature(f, sha)

def test_verify_signature_fail(tmp_path):
    f = tmp_path / "f.bin"
    f.write_text("dummy")
    assert not verify_signature(f, "00" * 32)

def test_load_config_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PAYLOAD_PATH", str(tmp_path / "p.bin"))
    cfg = load_config(None)
    assert cfg.payload_path.name == "p.bin"