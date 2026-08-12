"""
Dynamic Command Router for PayShield Host Commands.
"""

from typing import Dict, Type, Any, Optional
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
        if not self._handlers:
            import pythales.commands
        handler_cls = self._handlers.get(command_code.upper())
        if not handler_cls:
            raise PayShieldException(
                ErrorCodes.FUNCTION_NOT_SUPPORTED,
                f"Command '{command_code}' is not supported"
            )
        return handler_cls

    def dispatch(self, command_code: str, *args, **kwargs) -> Any:
        handler_cls = self.get_handler_class(command_code)
        if args or kwargs:
            if len(args) >= 1:
                handler = handler_cls(args[0])
                if hasattr(handler, "handle") and callable(getattr(handler, "handle")):
                    if len(args) >= 2:
                        return handler.handle(args[1])
                    return handler.handle()
                return handler
            return handler_cls(**kwargs)
        return handler_cls


global_router = CommandRouter()
Router = CommandRouter

