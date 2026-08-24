"""
Diagnostic and Miscellaneous Command Handlers: NC/ND, NO/NP, N0/N1.
"""

import os
from typing import Tuple
from pythales.commands.base import BaseCommandHandler
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException


@global_router.register("NC")
class NCHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        lmk_kcv = self.hsm.get_lmk_kcv_16()
        firmware_ver = b"0007-E000"
        return ErrorCodes.SUCCESS, lmk_kcv + firmware_ver


@global_router.register("NO")
class NOHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        # Network Echo Test: Echoes back the payload verbatim
        return ErrorCodes.SUCCESS, payload


@global_router.register("N0")
class N0Handler(BaseCommandHandler):
    """
    Host Command N0 / Response N1: Generate a Random Value.
    Root of Trust: Thales payShield 10K Core Host Commands Manual (Section 8.2, Pages 504-505).

    Request payload:
    - Random Value Length: 3 N (Decimal number in the range '001' to '256')

    Response payload on success ('00'):
    - Random Value: n B (Raw binary bytes of requested length)
    """

    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        if getattr(self.hsm, "command_n0_disabled", False) or getattr(
            self.hsm, "command_disabled", False
        ):
            return ErrorCodes.COMMAND_DISABLED, b""

        if len(payload) != 3:
            raise PayShieldException(
                ErrorCodes.INVALID_INPUT_DATA,
                "Random Value Length field must be exactly 3 digits",
            )

        try:
            length_str = payload.decode("ascii")
            if not length_str.isdigit():
                raise ValueError("Non-digit characters in length field")
            length = int(length_str)
        except Exception as exc:
            raise PayShieldException(
                ErrorCodes.INVALID_INPUT_DATA,
                "Random Value Length must be valid numeric characters",
            ) from exc

        if length < 1 or length > 256:
            raise PayShieldException(
                ErrorCodes.INVALID_RANDOM_VALUE_LENGTH,
                f"Random Value Length {length} out of range (001-256)",
            )

        random_bytes = os.urandom(length)
        return ErrorCodes.SUCCESS, random_bytes

