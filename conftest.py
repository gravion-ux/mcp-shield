"""Make the src/ layout importable when running pytest from the repo root
without installing the package first."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
