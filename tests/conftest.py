"""Shared fixtures / path helpers for the detection test suite."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections"
CASES_DIR = ROOT / "tests" / "cases"

# Allow `import dac` when pytest is run from a checkout without an install.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
