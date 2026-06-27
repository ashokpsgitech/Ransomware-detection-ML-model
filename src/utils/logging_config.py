"""Logging configuration stubs."""

from __future__ import annotations

import logging


def configure_logging(level: int = logging.INFO) -> None:
    """Configure application logging."""
    logging.basicConfig(level=level)
