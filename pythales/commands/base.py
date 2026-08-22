"""
Base Command Handler abstract class.
"""

from abc import ABC, abstractmethod
from typing import Tuple
from pythales.core.frame import CommandFrame, MessageFraming, ResponseFrame
from pythales.core.errors import ErrorCodes, PayShieldException



class BaseCommandHandler(ABC):
    def __init__(self, hsm_context):
        self.hsm = hsm_context

    @abstractmethod
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        Abstract method to process payload.
        Returns tuple of (error_code, response_payload_bytes).
        """
        pass

    def handle(self, request_frame: CommandFrame) -> ResponseFrame:
        response_code = self.get_response_code(request_frame.command_code)
        try:
            error_code, resp_payload = self.handle_payload(request_frame.payload_bytes)
        except PayShieldException as pe:
            error_code = pe.error_code
            resp_payload = b""
        except Exception:
            error_code = ErrorCodes.INTERNAL_HARDWARE_ERROR
            resp_payload = b""

        if request_frame.delimiter_present:
            resp_payload += b"\x19" + request_frame.trailer_bytes

        return ResponseFrame(
            header_bytes=request_frame.header_bytes,
            response_code=response_code,
            error_code=error_code,
            payload_bytes=resp_payload
        )

    def get_response_code(self, command_code: str) -> str:
        """Default response code mapping (e.g., NC -> ND, NO -> NP, A0 -> A1, CW -> CX, M0 -> M1)."""
        if len(command_code) == 2:
            first_char = command_code[0]
            second_char = command_code[1]
            # Replace second character if it follows A -> B, C -> D, O -> P, etc.
            next_char = chr(ord(second_char) + 1)
            return first_char + next_char
        return "ZZ"
