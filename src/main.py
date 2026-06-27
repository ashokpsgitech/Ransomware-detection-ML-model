"""Application entry point for the ransomware detection project."""

from __future__ import annotations

import logging


logger = logging.getLogger(__name__)


def main() -> None:
    """Start the ransomware detection application."""
    logger.info("Application startup requested.")
    raise NotImplementedError("Application orchestration will be implemented later.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
