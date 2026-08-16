"""Pytest configuration for unit tests in the PolicyAwareRAG project.

This file ensures the repository root is available on ``sys.path`` so the test
suite can import application modules without requiring installation.
"""

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
