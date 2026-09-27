"""Automotive TARA Assistant: AI-assisted ISO/SAE 21434 threat analysis and risk assessment."""

import os
from pathlib import Path

__version__ = "1.0.0"

# Project database and vector index. Defaults to <project>/data wherever the app is started from.
DATA_DIR = Path(os.environ.get("TARA_DATA_DIR") or Path(__file__).resolve().parents[1] / "data")
