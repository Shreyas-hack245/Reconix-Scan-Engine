"""
Logging configuration for Reconix Scan Engine.

Sets up both a human-readable application logger and ensures the
directory for the audit log file exists. The application logger is used
for operational/debug logging; the immutable, structured scan audit
trail is persisted separately in the database via app.models.audit_log
and app.utils (see the AuditLog model and scanner orchestrator).
"""

import logging
import os
import sys

from app.config import settings


def configure_logging() -> logging.Logger:
    """Configure and return the root application logger for Reconix Scan Engine."""
    log_dir = os.path.dirname(settings.audit_log_path) or "."
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("reconix")
    logger.setLevel(settings.log_level.upper())

    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        file_handler = logging.FileHandler(os.path.join(log_dir, "reconix.log"))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


logger = configure_logging()