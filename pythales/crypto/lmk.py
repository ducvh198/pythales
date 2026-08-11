"""
Thales PayShield LMK Engine with 64-bit XOR Variant Masks.
"""

from binascii import hexlify, unhexlify
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import pythales.compat

# 64-bit XOR variant masks applied to LMK halves
VARIANT_MASKS = {
    0: b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Base LMK / No Variant
    1: b"\x01\x00\x00\x00\x00\x00\x00\x00",  # ZMK / KEK
    2: b"\x02\x00\x00\x00\x00\x00\x00\x00",  # ZPK / TPK
    3: b"\x03\x00\x00\x00\x00\x00\x00\x00",  # PVK
    4: b"\x04\x00\x00\x00\x00\x00\x00\x00",  # CVK
    5: b"\x05\x00\x00\x00\x00\x00\x00\x00",  # BDK / DUKPT
    8: b"\x08\x00\x00\x00\x00\x00\x00\x00",  # DEK / Data Encryption Key
}


class LMKEngine:
    def __init__(self, base_lmk_bytes: bytes, enable_variants: bool = True):
        """
        Initialize LMK Engine with a 16-byte or 24-byte LMK.
        """
        if len(base_lmk_bytes) not in (16, 24):
            raise ValueError("LMK key must be 16 or 24 bytes long")
        self.base_lmk = base_lmk_bytes
        self.enable_variants = enable_variants

    def get_variant_lmk(self, variant: int = 0) -> bytes:
        if not self.enable_variants or variant == 0:
            return self.base_lmk

        mask = VARIANT_MASKS.get(variant, b"\x00" * 8)
        if len(self.base_lmk) == 16:
            left = bytes(a ^ b for a, b in zip(self.base_lmk[:8], mask))
            right = bytes(a ^ b for a, b in zip(self.base_lmk[8:16], mask))
            return left + right
        else: # 24 bytes
            k1 = bytes(a ^ b for a, b in zip(self.base_lmk[:8], mask))
            k2 = bytes(a ^ b for a, b in zip(self.base_lmk[8:16], mask))
            k3 = bytes(a ^ b for a, b in zip(self.base_lmk[16:24], mask))
            return k1 + k2 + k3

    def encrypt_under_lmk(self, key_bytes: bytes, variant: int = 0) -> bytes:
        var_lmk = self.get_variant_lmk(variant)
        cipher = Crypto.Cipher.DES3.new(var_lmk, Crypto.Cipher.DES3.MODE_ECB)
        return cipher.encrypt(key_bytes)

    def decrypt_under_lmk(self, encrypted_key_bytes: bytes, variant: int = 0) -> bytes:
        var_lmk = self.get_variant_lmk(variant)
        cipher = Crypto.Cipher.DES3.new(var_lmk, Crypto.Cipher.DES3.MODE_ECB)
        return cipher.decrypt(encrypted_key_bytes)

    @staticmethod
    def generate_kcv(key_bytes: bytes) -> str:
        """
        Generate 6-character hex Key Check Value (KCV) by encrypting 8 zero bytes.
        """
        cipher = Crypto.Cipher.DES3.new(key_bytes, Crypto.Cipher.DES3.MODE_ECB)
        encrypted_zeros = cipher.encrypt(b"\x00" * 8)
        return hexlify(encrypted_zeros[:3]).decode("ascii").upper()
