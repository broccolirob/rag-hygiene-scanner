import subprocess
import sys

import rag_hygiene_scan as pkg


def test_import_and_version():
    assert hasattr(pkg, "__version__")


def test_cli_help():
    # Ensure CLI entrypoint is wired and help prints
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "show", "rag-hygiene-scan"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0  # package installed

    proc2 = subprocess.run(["rag-scan", "--help"], capture_output=True, text=True)
    assert proc2.returncode == 0
    assert "Scan Markdown/HTML/txt" in proc2.stdout
