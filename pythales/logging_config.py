"""Logging helpers for PyThales applications."""

import logging
import sys


_CONSOLE_HANDLER_MARKER = "_pythales_console_handler"
_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"


def configure_console_logging(debug=False, stream=None):
    """Configure an idempotent console handler for all ``pythales`` loggers."""
    package_logger = logging.getLogger("pythales")
    level = logging.DEBUG if debug else logging.INFO
    output_stream = stream if stream is not None else sys.stdout

    console_handler = None
    for handler in package_logger.handlers:
        if getattr(handler, _CONSOLE_HANDLER_MARKER, False):
            console_handler = handler
            break

    if console_handler is None:
        console_handler = logging.StreamHandler(output_stream)
        setattr(console_handler, _CONSOLE_HANDLER_MARKER, True)
        console_handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT))
        package_logger.addHandler(console_handler)
    elif stream is not None:
        console_handler.setStream(output_stream)

    console_handler.setLevel(level)
    package_logger.setLevel(level)
    # This handler owns PyThales console output; do not duplicate it through root.
    package_logger.propagate = False
    return package_logger
