"""
Diagnostic Command Handlers: NC/ND, NO/NP.
"""

from typing import Tuple
from pythales.commands.base import BaseCommandHandler
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes


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
