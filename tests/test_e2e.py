"""
test_e2e.py — End-to-end loopback test via main.py test command.

Runs `python -X utf8 main.py test --size 2 --port 19800` as a subprocess
and verifies the output contains "SELF-TEST PASSED".
"""
import sys
import os
import subprocess

# Resolve the project root (one level up from tests/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_loopback_sha_match():
    """2 MiB loopback transfer: SHA-256 must match on sender and receiver."""
    result = subprocess.run(
        [sys.executable, "-X", "utf8", "main.py", "test",
         "--size", "2", "--port", "19800"],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=_PROJECT_ROOT,
    )
    combined = result.stdout + result.stderr
    assert "SELF-TEST PASSED" in combined, (
        f"Expected 'SELF-TEST PASSED' in output, but got:\n{combined}"
    )
