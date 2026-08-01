"""Local-only logging helpers.

Macaw never configures a network logging sink. Callers may opt into a local log
file for troubleshooting.
"""

from __future__ import annotations

import logging
from pathlib import Path


def get_logger(name: str = "macaw", log_file: Path | None = None) -> logging.Logger:
    """Return a logger that is silent unless a local file was explicitly chosen."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if log_file is not None and not any(
        isinstance(handler, logging.FileHandler) and handler.baseFilename == str(log_file)
        for handler in logger.handlers
    ):
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger

