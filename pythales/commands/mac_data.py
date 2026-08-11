"""
Data Encryption Command Handlers: M0/M1 (Encrypt Data), M2/M3 (Decrypt Data).
"""

from binascii import hexlify, unhexlify
from typing import Tuple
import Crypto.Cipher.DES3
from pythales.commands.base import BaseCommandHandler
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException


def pad_pkcs5(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs5(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 8 and data.endswith(bytes([pad_len] * pad_len)):
        return data[:-pad_len]
    return data


@global_router.register("M0")
class M0Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M0 Encrypt Data Handler.
        Payload: [DEK: scheme + 32 hex] + [Mode: '0'=ECB, '1'=CBC] + [DataLength: 4 hex digits] + [Data] (+ [IV: 16 hex] if CBC)
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 33 + 1 + 4:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M0 payload too short")

        dek_str = payload_str[:33]
        mode = payload_str[33]
        data_len = int(payload_str[34:38], 16)
        remaining = payload_str[38:]

        enc_dek = unhexlify(dek_str[1:])
        dek_raw = self.hsm.lmk_engine.decrypt_under_lmk(enc_dek, variant=8)  # Variant 8 for DEK

        data_bytes = unhexlify(remaining[: data_len * 2]) if len(remaining) >= data_len * 2 else remaining.encode("ascii")
        padded_data = pad_pkcs5(data_bytes, 8)

        if mode == "0":  # ECB
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_ECB)
            encrypted = cipher.encrypt(padded_data)
        elif mode == "1":  # CBC
            iv_hex = remaining[data_len * 2 : data_len * 2 + 16] if len(remaining) >= data_len * 2 + 16 else "0000000000000000"
            iv_bytes = unhexlify(iv_hex)
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_CBC, iv=iv_bytes)
            encrypted = cipher.encrypt(padded_data)
        else:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Unsupported encryption mode")

        return ErrorCodes.SUCCESS, hexlify(encrypted).upper()


@global_router.register("M2")
class M2Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M2 Decrypt Data Handler.
        Payload: [DEK: scheme + 32 hex] + [Mode: '0'=ECB, '1'=CBC] + [DataLength: 4 hex digits] + [EncryptedHex] (+ [IV: 16 hex] if CBC)
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 33 + 1 + 4:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M2 payload too short")

        dek_str = payload_str[:33]
        mode = payload_str[33]
        data_len = int(payload_str[34:38], 16)
        remaining = payload_str[38:]

        enc_dek = unhexlify(dek_str[1:])
        dek_raw = self.hsm.lmk_engine.decrypt_under_lmk(enc_dek, variant=8)

        encrypted_bytes = unhexlify(remaining[: data_len * 2])

        if mode == "0":  # ECB
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_ECB)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
        elif mode == "1":  # CBC
            iv_hex = remaining[data_len * 2 : data_len * 2 + 16] if len(remaining) >= data_len * 2 + 16 else "0000000000000000"
            iv_bytes = unhexlify(iv_hex)
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_CBC, iv=iv_bytes)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
        else:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Unsupported encryption mode")

        decrypted = unpad_pkcs5(decrypted_padded)
        return ErrorCodes.SUCCESS, hexlify(decrypted).upper()
