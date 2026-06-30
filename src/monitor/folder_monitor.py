"""Folder monitoring using watchdog."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.extractor.pe_extractor import PEFeatureExtractor

logger = logging.getLogger(__name__)


class ExecutableHandler(FileSystemEventHandler):
    """Event handler to detect executable creations and modifications."""

    def __init__(
        self,
        on_executable_detected: Callable[[Path], None],
        debounce_seconds: float = 2.0,
    ) -> None:
        """Initialize the handler with a callback and debounce timer."""
        self.on_executable_detected = on_executable_detected
        self.extractor = PEFeatureExtractor()
        self.debounce_seconds = debounce_seconds
        self.processed_files: dict[str, float] = {}

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if event.is_directory:
            return
        self._check_and_trigger(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if event.is_directory:
            return
        self._check_and_trigger(Path(event.src_path))

    def _check_and_trigger(self, file_path: Path) -> None:
        """Validate and trigger the callback, applying debouncing."""
        # Normalize the path string
        path_str = str(file_path.resolve())

        # Apply debouncing to prevent double-processing on rapid file writes
        now = time.time()
        last_processed = self.processed_files.get(path_str, 0.0)
        if now - last_processed < self.debounce_seconds:
            return

        # Validate whether it is a PE executable (valid MZ headers etc.)
        # This will fail while the file is still being written to, which is good.
        if self.extractor.validate_file(file_path):
            self.processed_files[path_str] = now
            logger.info("New/modified executable detected: %s", file_path.name)
            
            # Allow a tiny sleep to ensure the file handles are released by the OS/downloader
            time.sleep(0.5)
            try:
                self.on_executable_detected(file_path)
            except Exception as e:
                logger.error("Error running executable callback: %s", e)


class FolderMonitor:
    """Monitor a folder for newly created or modified executable files."""

    def __init__(self, watch_path: Path, on_executable_detected: Callable[[Path], None]) -> None:
        """Initialize the monitor with a watch path and callback."""
        self.watch_path = Path(watch_path)
        self.on_executable_detected = on_executable_detected
        self.observer: Observer | None = None

    def start(self) -> None:
        """Start watching the configured folder."""
        logger.info("Starting folder monitor on directory: %s", self.watch_path)
        if not self.watch_path.exists():
            logger.info("Watch directory does not exist. Creating it: %s", self.watch_path)
            self.watch_path.mkdir(parents=True, exist_ok=True)

        event_handler = ExecutableHandler(self.on_executable_detected)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.watch_path), recursive=False)
        self.observer.start()
        logger.info("Folder monitor started successfully.")

    def stop(self) -> None:
        """Stop watching the configured folder."""
        if self.observer is not None:
            logger.info("Stopping folder monitor observer...")
            self.observer.stop()
            self.observer.join()
            self.observer = None
            logger.info("Folder monitor stopped.")
