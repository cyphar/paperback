import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "release" / "paperback"


def test_version():
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    result = subprocess.run(
        [str(BINARY), "--version"], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == f"paperback-cli {version}"
