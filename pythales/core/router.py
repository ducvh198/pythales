"""
Dynamic Command Router for PayShield Host Commands.
"""

from typing import Dict, Type, Optional
from pythales.core.errors import PayShieldException, ErrorCodes


class CommandRouter:
    def __init__(self):
        self._handlers: Dict[str, Type] = {}

    def register(self, command_code: str):
        """Decorator to register a command handler for a 2-character command code."""
        def decorator(cls):
            self._handlers[command_code.upper()] = cls
            return cls
        return decorator

    def get_handler_class(self, command_code: str) -> Type:
        handler_cls = self._handlers.get(command_code.upper())
        if not handler_cls:
            raise PayShieldException(
                ErrorCodes.FUNCTION_NOT_SUPPORTED,
                f"Command '{command_code}' is not supported"
            )
        return handler_cls

    def dispatch(self, command_code: str, hsm_context, request_frame) -> bytes:
        handler_cls = self.get_handler_class(command_code)
        handler = handler_cls(hsm_context)
        return handler.handle(request_frame)


global_router = CommandRouter()
