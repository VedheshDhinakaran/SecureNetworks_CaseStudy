"""Make the shared `common/sjvnet` package importable when tools run as scripts."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
