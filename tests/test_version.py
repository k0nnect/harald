import subprocess
import sys

import harald


def test_version_string():
    assert harald.__version__ == "0.2.2"


def test_module_runs():
    out = subprocess.run(
        [sys.executable, "-m", "harald", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0 and out.stdout.strip() == "harald 0.2.2"
