"""
Key Management Command Handlers: A0/A1, BU/BV.
"""

import os
from binascii import hexlify, unhexlify
from typing import Tuple
from pythales.commands.base import BaseCommandHandler
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.lmk import LMKEngine

# Map PayShield Key Types to LMK Variants
KEY_TYPE_VARIANTS = {
    "000": 1,  # ZMK / KEK
    "001": 2,  # ZPK / TPK
    "002": 3,  # PVK
    "003": 4,  # CVK
    "005": 5,  # BDK / DUKPT
    "008": 8,  # DEK
}


@global_router.register("A0")
class A0Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        A0 Generate Key Handler.
        Payload format:
        [Mode: 1 char ('0'=LMK, '1'=ZMK)] + [KeyType: 3 chars ('000'..'008')] + [KeyScheme: 1 char ('U'/'X'/'Y')]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 5:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "A0 payload too short")

        mode = payload_str[0]
        key_type = payload_str[1:4]
        key_scheme = payload_str[4]

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        
        # Generate random 16-byte (Double-length 3DES) key
        raw_key = os.urandom(16)
        
        # Encrypt key under LMK using variant
        enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
        key_lmk_hex = key_scheme.encode("ascii") + hexlify(enc_key_lmk).upper()

        # KCV
        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")

        if mode == "0":
            return ErrorCodes.SUCCESS, key_lmk_hex + kcv
        elif mode == "1":
            # Under ZMK mode requires ZMK in payload
            zmk_hex = payload_str[5:38] if len(payload_str) >= 38 else ""
            if not zmk_hex:
                raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Missing ZMK for mode 1")
            
            zmk_scheme = zmk_hex[0]
            zmk_enc = unhexlify(zmk_hex[1:])
            zmk_raw = self.hsm.lmk_engine.decrypt_under_lmk(zmk_enc, variant=1)
            
            # Encrypt key under ZMK
            enc_key_zmk = LMKEngine(zmk_raw).encrypt_under_lmk(raw_key, variant=0)
            key_zmk_hex = key_scheme.encode("ascii") + hexlify(enc_key_zmk).upper()
            
            return ErrorCodes.SUCCESS, key_lmk_hex + key_zmk_hex + kcv
        else:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Invalid mode")


@global_router.register("BU")
class BUHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        BU Generate KCV Handler.
        Payload: [KeyType: 3 chars] + [KeyUnderLMK: 1 char scheme + hex]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 4:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "BU payload too short")

        key_type = payload_str[:3]
        key_str = payload_str[3:]

        key_scheme = key_str[0]
        enc_key = unhexlify(key_str[1:])

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        raw_key = self.hsm.lmk_engine.decrypt_under_lmk(enc_key, variant)
        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")

        return ErrorCodes.SUCCESS, kcv
