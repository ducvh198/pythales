"""
Thales PayShield LMK Engine with 64-bit XOR Variant Masks.
"""

from binascii import hexlify, unhexlify
from typing import Union, Optional
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import Crypto.Cipher.AES
from Crypto.Hash import CMAC
import pythales.compat
from pythales.core.errors import PayShieldException, ErrorCodes


# 64-bit XOR variant masks applied to LMK halves
VARIANT_MASKS = {
    0: b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Base LMK / No Variant
    1: b"\x01\x00\x00\x00\x00\x00\x00\x00",  # ZMK / KEK
    2: b"\x02\x00\x00\x00\x00\x00\x00\x00",  # ZPK / TPK / TMK
    3: b"\x03\x00\x00\x00\x00\x00\x00\x00",  # PVK / TPVP
    4: b"\x04\x00\x00\x00\x00\x00\x00\x00",  # CVK / TAK
    5: b"\x05\x00\x00\x00\x00\x00\x00\x00",  # BDK / DUKPT
    6: b"\x06\x00\x00\x00\x00\x00\x00\x00",  # ZAK
    7: b"\x07\x00\x00\x00\x00\x00\x00\x00",  # PCI TPK/TMK Pair 36-37 (Variant 7)
    8: b"\x08\x00\x00\x00\x00\x00\x00\x00",  # DEK / PCI TPK/TMK Pair 36-37 (Variant 8)
    9: b"\x09\x00\x00\x00\x00\x00\x00\x00",  # MDK / KCK
}


class LMKEngine:
    def __init__(self, base_lmk_bytes: bytes, enable_variants: bool = True, pci_mode: bool = True):
        """
        Initialize LMK Engine with a 16-byte or 24-byte LMK.
        """
        if len(base_lmk_bytes) not in (16, 24):
            raise ValueError("LMK key must be 16 or 24 bytes long")
        self.base_lmk = base_lmk_bytes
        self.enable_variants = enable_variants
        self.pci_mode = pci_mode

    def get_variant_lmk(self, variant: Union[int, str] = 0) -> bytes:
        if isinstance(variant, str):
            try:
                var_num = int(variant)
            except ValueError:
                raise PayShieldException(
                    ErrorCodes.INVALID_KEY_SCHEME,
                    f"Invalid LMK variant value: '{variant}'"
                )
        else:
            var_num = int(variant)

        if var_num < 0 or var_num > 9:
            raise PayShieldException(
                ErrorCodes.INVALID_KEY_SCHEME,
                f"Unsupported LMK variant {var_num}. Variants must be 0-9."
            )

        if not self.enable_variants or var_num == 0:
            return self.base_lmk

        mask = VARIANT_MASKS[var_num]
        if len(self.base_lmk) == 16:
            left = bytes(a ^ b for a, b in zip(self.base_lmk[:8], mask))
            right = bytes(a ^ b for a, b in zip(self.base_lmk[8:16], mask))
            return left + right
        else:  # 24 bytes
            k1 = bytes(a ^ b for a, b in zip(self.base_lmk[:8], mask))
            k2 = bytes(a ^ b for a, b in zip(self.base_lmk[8:16], mask))
            k3 = bytes(a ^ b for a, b in zip(self.base_lmk[16:24], mask))
            return k1 + k2 + k3

    def encrypt_under_lmk(self, key_bytes: bytes, variant: Union[int, str] = 0) -> bytes:
        var_lmk = self.get_variant_lmk(variant)
        cipher = Crypto.Cipher.DES3.new(var_lmk, Crypto.Cipher.DES3.MODE_ECB)
        return cipher.encrypt(key_bytes)

    def decrypt_under_lmk(self, encrypted_key_bytes: bytes, variant: Union[int, str] = 0) -> bytes:
        var_lmk = self.get_variant_lmk(variant)
        cipher = Crypto.Cipher.DES3.new(var_lmk, Crypto.Cipher.DES3.MODE_ECB)
        return cipher.decrypt(encrypted_key_bytes)

    def validate_pci_key_separation(self, key_type: Union[str, bytes], variant: Union[int, str], pci_mode: Optional[bool] = None) -> bool:
        """
        Enforce PCI HSM key separation rule:
        TPK/TMK LMK Pair 36-37 MUST use Variant 7 or 8.
        If pci_mode is enabled and generic variant 2 (or non-7/8 variant) is used for TPK/TMK,
        raise PayShieldException with PCI_KEY_SEPARATION_VIOLATION ('A7').
        """
        enforce = self.pci_mode if pci_mode is None else pci_mode
        if not enforce:
            return True

        kt_str = key_type.decode("ascii", errors="ignore").upper() if isinstance(key_type, bytes) else str(key_type).upper()
        var_num = int(variant) if not isinstance(variant, int) else variant

        if kt_str in ("002", "003", "TPK", "TMK", "PAIR36_37", "000"):
            if var_num in (1, 2) and var_num not in (7, 8):
                raise PayShieldException(
                    ErrorCodes.PCI_KEY_SEPARATION_VIOLATION,
                    f"PCI HSM Policy Violation: Key Type {kt_str} requires LMK Pair 36-37 (Variant 7/8), got Variant {var_num}"
                )
        return True

    def validate_dek_protection(self, key_type: Union[str, bytes], variant: Union[int, str], export_scheme: Optional[str] = None) -> bool:
        """
        Enforce DEK Variant 8 protection / no-downgrade rule support:
        1. DEK (Key Type 008) MUST use Variant 8 when encrypted under LMK.
        2. DEK cannot be exported under cleartext or legacy un-versioned variant schemes ('U', 'X') without Key Block wrapping.
        Raises PayShieldException with DEK_DOWNGRADE_PROHIBITED ('A8').
        """
        kt_str = key_type.decode("ascii", errors="ignore").upper() if isinstance(key_type, bytes) else str(key_type).upper()
        var_num = int(variant) if not isinstance(variant, int) else variant

        if kt_str in ("008", "DEK"):
            if var_num != 8 and var_num != 0:
                raise PayShieldException(
                    ErrorCodes.DEK_DOWNGRADE_PROHIBITED,
                    f"DEK Protection Rule Violation: DEK must use LMK Variant 8, got Variant {var_num}"
                )
            if export_scheme in ("U", "X", "CLEAR", "LEGACY"):
                raise PayShieldException(
                    ErrorCodes.DEK_DOWNGRADE_PROHIBITED,
                    f"DEK Protection Rule Violation: DEK downgrade to scheme '{export_scheme}' is prohibited. Must use Key Block."
                )
        return True

    @staticmethod
    def generate_kcv(key_bytes: bytes, algorithm: str = "T") -> str:
        """
        Generate 6-character hex Key Check Value (KCV).
        - For 3DES (algorithm 'T'): Encrypt 8 zero bytes using DES3 ECB and take first 3 bytes hex.
        - For AES (algorithm 'A', 'A1', 'A2', 'A3'): AES-CMAC on 16 zero bytes and take first 3 bytes hex.
        """
        if algorithm.upper().startswith("A") or len(key_bytes) == 32:
            try:
                c_obj = CMAC.new(key_bytes, ciphermod=Crypto.Cipher.AES)
                c_obj.update(b"\x00" * 16)
                cmac_bytes = c_obj.digest()
                return hexlify(cmac_bytes[:3]).decode("ascii").upper()
            except Exception:
                cipher = Crypto.Cipher.AES.new(key_bytes, Crypto.Cipher.AES.MODE_ECB)
                enc_zeros = cipher.encrypt(b"\x00" * 16)
                return hexlify(enc_zeros[:3]).decode("ascii").upper()
        else:
            cipher = Crypto.Cipher.DES3.new(key_bytes, Crypto.Cipher.DES3.MODE_ECB)
            encrypted_zeros = cipher.encrypt(b"\x00" * 8)
            return hexlify(encrypted_zeros[:3]).decode("ascii").upper()



