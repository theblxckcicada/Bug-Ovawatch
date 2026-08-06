"""Pytest bootstrap — put the backend package root on sys.path.

The backend uses flat, top-level imports (``import models``, ``from tools.base
import BaseTool``, ``import process_registry``). Adding the backend directory to
``sys.path`` lets the test suite import those modules exactly as the app does,
without needing an installed package or a src layout.
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
