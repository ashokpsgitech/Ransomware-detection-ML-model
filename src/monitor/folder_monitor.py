"""Folder monitoring stubs."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path


logger = logging.getLogger(__name__)


class FolderMonitor:
    """Monitor a folder for newly created executable files."""

    def __init__(self, watch_path: Path, on_executable_detected: Callable[[Path], None]) -> None:
        """Initialize the monitor with a watch path and callback."""
        self.watch_path = watch_path
        self.on_executable_detected = on_executable_detected

    def start(self) -> None:
        """Start watching the configured folder."""
        logger.info("Folder monitoring start requested for %s.", self.watch_path)
        raise NotImplementedError("Folder monitoring will be implemented later.")

    def stop(self) -> None:
        """Stop watching the configured folder."""
        logger.info("Folder monitoring stop requested for %s.", self.watch_path)
        raise NotImplementedError("Folder monitor shutdown will be implemented later.")
