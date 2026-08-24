"""Tests for opt-in PyThales console logging."""

import io
import logging

from pythales.logging_config import configure_console_logging


def _remove_test_console_handler():
    package_logger = logging.getLogger("pythales")
    for handler in list(package_logger.handlers):
        if getattr(handler, "_pythales_console_handler", False):
            package_logger.removeHandler(handler)
            handler.close()


def test_debug_logging_is_written_to_console():
    stream = io.StringIO()
    try:
        configure_console_logging(debug=True, stream=stream)

        logging.getLogger("pythales.server").debug("request payload: 4E43")

        output = stream.getvalue()
        assert "DEBUG pythales.server" in output
        assert "request payload: 4E43" in output
    finally:
        _remove_test_console_handler()


def test_console_logging_configuration_is_idempotent():
    stream = io.StringIO()
    try:
        configure_console_logging(debug=True, stream=stream)
        configure_console_logging(debug=True, stream=stream)

        logging.getLogger("pythales.hsm").debug("only once")

        assert stream.getvalue().count("only once") == 1
    finally:
        _remove_test_console_handler()
