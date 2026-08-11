"""
Card Verification Command Handlers: CW/CX (Generate CVV), CY/CZ (Verify CVV).
"""

from binascii import hexlify, unhexlify
from typing import Tuple
import Crypto.Cipher.DES3
from pythales.commands.base import BaseCommandHandler
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException


def calculate_cvv(cvk_bytes: bytes, pan: str, exp_date: str, service_code: str) -> str:
    """
    Standard Visa/Mastercard CVV/CVV2 calculation algorithm.
    Block 1 = 12 digits PAN + 4 digits Exp Date
    Block 2 = 3 digits Service Code + 13 zeros
    Data = Block 1 (8 bytes hex) + Block 2 (8 bytes hex)
    """
    # Format 16-digit data block
    formatted_pan = pan.rjust(16, "0")[-16:]
    formatted_exp = exp_date.rjust(4, "0")
    formatted_svc = service_code.rjust(3, "0")

    block1_str = formatted_pan[:12] + formatted_exp
    block2_str = formatted_svc + "0" * 13

    block1_bytes = unhexlify(block1_str)
    block2_bytes = unhexlify(block2_str)

    # 3DES Encrypt block 1 with CVK
    cvk1 = cvk_bytes[:8]
    cvk2 = cvk_bytes[8:16]
    
    # Encrypt block1 with CVK1
    des1 = Crypto.Cipher.DES.new(cvk1, Crypto.Cipher.DES.MODE_ECB)
    enc1 = des1.encrypt(block1_bytes)
    
    # XOR with block2
    xor_res = bytes(a ^ b for a, b in zip(enc1, block2_bytes))

    # 3DES encrypt xor_res with CVK
    cipher3des = Crypto.Cipher.DES3.new(cvk_bytes, Crypto.Cipher.DES3.MODE_ECB)
    enc_final = cipher3des.encrypt(xor_res)
    enc_hex = hexlify(enc_final).decode("ascii").upper()

    # Extract digits from enc_hex: first decimal digits, then mapping hex A-F to 0-5
    digits = [c for c in enc_hex if c.isdigit()]
    other_digits = [str(int(c, 16) - 10) for c in enc_hex if not c.isdigit()]
    all_digits = digits + other_digits

    return "".join(all_digits[:3])


@global_router.register("CW")
class CWHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        CW Generate CVV Handler.
        Payload: [CVK: scheme + 32 hex] + [PAN: 16 digits] + [ExpDate: 4 digits] + [ServiceCode: 3 digits]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 33 + 16 + 4 + 3:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "CW payload too short")

        cvk_str = payload_str[:33]
        pan = payload_str[33:49]
        exp_date = payload_str[49:53]
        service_code = payload_str[53:56]

        enc_cvk = unhexlify(cvk_str[1:])
        cvk_raw = self.hsm.lmk_engine.decrypt_under_lmk(enc_cvk, variant=4)  # Variant 4 for CVK

        cvv = calculate_cvv(cvk_raw, pan, exp_date, service_code)
        return ErrorCodes.SUCCESS, cvv.encode("ascii")


@global_router.register("CY")
class CYHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        CY Verify CVV Handler.
        Payload: [CVK: scheme + 32 hex] + [CVV: 3 digits] + [PAN: 16 digits] + [ExpDate: 4 digits] + [ServiceCode: 3 digits]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 33 + 3 + 16 + 4 + 3:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "CY payload too short")

        cvk_str = payload_str[:33]
        expected_cvv = payload_str[33:36]
        pan = payload_str[36:52]
        exp_date = payload_str[52:56]
        service_code = payload_str[56:59]

        enc_cvk = unhexlify(cvk_str[1:])
        cvk_raw = self.hsm.lmk_engine.decrypt_under_lmk(enc_cvk, variant=4)

        calculated_cvv = calculate_cvv(cvk_raw, pan, exp_date, service_code)
        if calculated_cvv == expected_cvv:
            return ErrorCodes.SUCCESS, b""
        else:
            return ErrorCodes.LMK_ERROR, b""  # Verification failure code '01'
