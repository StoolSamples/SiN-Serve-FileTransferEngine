"""
test_resume.py — Integration tests for sidecar-based resume.
"""
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock

from receiver import FileReceiver, SidecarManager


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_config(resume_enabled=True):
    cfg = MagicMock()
    cfg.resume_enabled = resume_enabled
    cfg.crypto_enabled = False
    return cfg


def _make_meta(filename="test.bin", file_size=1024000,
               total_chunks=100, chunk_size=10240):
    sha = bytes(32)
    return {
        "filename":     filename,
        "file_size":    file_size,
        "total_chunks": total_chunks,
        "chunk_size":   chunk_size,
        "file_sha256":  sha,
    }


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_load_resume_state_disabled():
    """When resume_enabled is False, _load_resume_state must return an empty set
    regardless of any sidecar file on disk."""
    cfg = _make_config(resume_enabled=False)
    recv = FileReceiver(cfg)
    meta = _make_meta()
    session_id = b"\x00" * 16

    result = recv._load_resume_state("/any/path", meta, session_id)

    assert result == set()


def test_load_resume_state_no_sidecar(tmp_path):
    """When resume_enabled is True but no sidecar file exists, the method must
    return an empty set."""
    cfg = _make_config(resume_enabled=True)
    recv = FileReceiver(cfg)
    meta = _make_meta()
    session_id = b"\x00" * 16

    output_path = str(tmp_path / "test.bin")
    # Ensure the sidecar file does not exist
    sidecar_path = output_path + SidecarManager.SIDECAR_SUFFIX
    assert not os.path.exists(sidecar_path)

    result = recv._load_resume_state(output_path, meta, session_id)

    assert result == set()


def test_load_resume_state_happy_path(tmp_path):
    """A valid sidecar whose metadata matches meta must return the set of
    written chunk IDs recorded in that sidecar."""
    output_path = str(tmp_path / "test.bin")
    sidecar_path = output_path + SidecarManager.SIDECAR_SUFFIX

    sidecar_content = {
        "version":       1,
        "filename":      "test.bin",
        "file_size":     1024000,
        "total_chunks":  100,
        "chunk_size":    10240,
        "file_sha256":   bytes(32).hex(),
        "written_chunks": list(range(50)),
    }
    with open(sidecar_path, "w", encoding="utf-8") as fh:
        json.dump(sidecar_content, fh)

    cfg = _make_config(resume_enabled=True)
    recv = FileReceiver(cfg)
    meta = _make_meta()
    session_id = b"\x00" * 16

    result = recv._load_resume_state(output_path, meta, session_id)

    assert result == set(range(50))


def test_validate_sidecar_mismatch():
    """A sidecar whose filename differs from meta's filename must fail
    validation."""
    meta = _make_meta(filename="test.bin")
    sidecar = {
        "filename":      "wrong.bin",   # intentional mismatch
        "file_size":     meta["file_size"],
        "total_chunks":  meta["total_chunks"],
        "chunk_size":    meta["chunk_size"],
        "file_sha256":   meta["file_sha256"].hex(),
    }

    assert FileReceiver._validate_sidecar(sidecar, meta) == False


def test_validate_sidecar_match():
    """A sidecar whose every field matches meta must pass validation."""
    meta = _make_meta(filename="test.bin")
    sidecar = {
        "filename":      meta["filename"],
        "file_size":     meta["file_size"],
        "total_chunks":  meta["total_chunks"],
        "chunk_size":    meta["chunk_size"],
        "file_sha256":   meta["file_sha256"].hex(),
    }

    assert FileReceiver._validate_sidecar(sidecar, meta) == True
