"""
Card Verification Command Handlers: CW/CX (Generate CVV), CY/CZ (Verify CVV).
"""

from binascii import hexlify, unhexlify
from typing import Tuple
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
from pythales.commands.base import BaseCommandHandler
from pythales.commands.key_mgmt import _extract_key_string
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock


def _decrypt_cvk(hsm, key_str: str) -> bytes:
    scheme = key_str[0].upper()
    if scheme == "S":
        _, clear_key = TR31KeyBlock.unwrap(key_str, hsm.LMK)
        return clear_key
    elif scheme in ("U", "X"):
        enc_bytes = unhexlify(key_str[1:33])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=4)
    elif scheme in ("T", "Y"):
        enc_bytes = unhexlify(key_str[1:49])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=4)
    elif scheme in ("Z", "D", "E", "A"):
        enc_bytes = unhexlify(key_str[1:])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=4)
    else:
        enc_bytes = unhexlify(key_str)
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=4)


def calculate_cvv(cvk_bytes: bytes, pan: str, exp_date: str, service_code: str) -> str:
    """
    Standard Visa/Mastercard CVV/CVV2 calculation algorithm.
    """
    formatted_pan = pan.rjust(16, "0")[-16:]
    formatted_exp = exp_date.rjust(4, "0")
    formatted_svc = service_code.rjust(3, "0")

    block1_str = formatted_pan[:12] + formatted_exp
    block2_str = formatted_svc + "0" * 13

    block1_bytes = unhexlify(block1_str)
    block2_bytes = unhexlify(block2_str)

    cvk1 = cvk_bytes[:8]
    cvk2 = cvk_bytes[8:16] if len(cvk_bytes) >= 16 else cvk1

    des1 = Crypto.Cipher.DES.new(cvk1, Crypto.Cipher.DES.MODE_ECB)
    enc1 = des1.encrypt(block1_bytes)

    xor_res = bytes(a ^ b for a, b in zip(enc1, block2_bytes))

    if len(cvk_bytes) < 16:
        cvk_bytes = cvk_bytes + cvk_bytes
    cipher3des = Crypto.Cipher.DES3.new(cvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)
    enc_final = cipher3des.encrypt(xor_res)
    enc_hex = hexlify(enc_final).decode("ascii").upper()

    digits = [c for c in enc_hex if c.isdigit()]
    other_digits = [str(int(c, 16) - 10) for c in enc_hex if not c.isdigit()]
    all_digits = digits + other_digits

    return "".join(all_digits[:3])


@global_router.register("CW")
class CWHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        CW Generate CVV Handler.
        Supports field separation with ';' delimiter between PAN, Expiration Date (YYMM), and Service Code (3 digits).
        Calculates CVV using CVK under LMK Variant 4.
        Returns response code 'CX', error '00', 3-digit CVV.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 17:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "CW payload too short")

        cvk_str, rem = _extract_key_string(payload_str)
        rem = rem.lstrip(";").rstrip("?")

        if ";" in rem:
            parts = rem.split(";")
            pan = parts[0]
            if "=" in pan:
                pan, rest = pan.split("=", 1)
                exp_date = rest[:4]
                service_code = rest[4:7]
            elif len(parts) >= 3:
                exp_date = parts[1]
                service_code = parts[2]
            elif len(parts) == 2:
                exp_date = parts[1][:4]
                service_code = parts[1][4:7]
            else:
                exp_date = ""
                service_code = ""
        elif "=" in rem:
            pan, rest = rem.split("=", 1)
            exp_date = rest[:4]
            service_code = rest[4:7]
        else:
            pan = rem[:-7]
            exp_date = rem[-7:-3]
            service_code = rem[-3:]

        pan = "".join([c for c in pan if c.isdigit()])
        exp_date = "".join([c for c in exp_date if c.isdigit()])[:4]
        service_code = "".join([c for c in service_code if c.isdigit()])[:3]

        cvk_raw = _decrypt_cvk(self.hsm, cvk_str)

        cvv = calculate_cvv(cvk_raw, pan, exp_date, service_code)
        return ErrorCodes.SUCCESS, cvv.encode("ascii")


@global_router.register("CY")
class CYHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        CY Verify CVV Handler.
        Supports field separation with ';' delimiter between PAN, Expiration Date, Service Code, and CVV to verify.
        Supports Track 2 layout (CVV;PAN=YYMMSVC...).
        Returns response code 'CZ', error '00' on match or '01' on mismatch.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 17:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "CY payload too short")

        cvk_str, rem = _extract_key_string(payload_str)
        rem = rem.rstrip("?")

        raw_parts = rem.split(";")
        non_empty_parts = [p for p in raw_parts if p]

        if ";" in rem:
            has_equals_part = any("=" in p for p in non_empty_parts)
            if has_equals_part:
                if len(non_empty_parts) >= 2:
                    if "=" in non_empty_parts[1]:
                        expected_cvv = non_empty_parts[0]
                        pan, rest = non_empty_parts[1].split("=", 1)
                        exp_date = rest[:4]
                        service_code = rest[4:7]
                    else:
                        pan, rest = non_empty_parts[0].split("=", 1)
                        exp_date = rest[:4]
                        service_code = rest[4:7]
                        expected_cvv = non_empty_parts[1]
                else:
                    pan, rest = non_empty_parts[0].split("=", 1)
                    exp_date = rest[:4]
                    service_code = rest[4:7]
                    expected_cvv = rest[7:10] if len(rest) >= 10 else ""
            elif len(non_empty_parts) >= 4:
                if len(non_empty_parts[0]) == 3 and non_empty_parts[0].isdigit() and len(non_empty_parts[1]) >= 12:
                    expected_cvv = non_empty_parts[0]
                    pan = non_empty_parts[1]
                    exp_date = non_empty_parts[2]
                    service_code = non_empty_parts[3]
                else:
                    pan = non_empty_parts[0]
                    exp_date = non_empty_parts[1]
                    service_code = non_empty_parts[2]
                    expected_cvv = non_empty_parts[3]
            elif len(non_empty_parts) == 3:
                if len(non_empty_parts[2]) == 3 and non_empty_parts[2].isdigit():
                    pan = non_empty_parts[0]
                    exp_date = non_empty_parts[1][:4]
                    service_code = non_empty_parts[1][4:7]
                    expected_cvv = non_empty_parts[2]
                else:
                    expected_cvv = non_empty_parts[0]
                    pan = non_empty_parts[1]
                    exp_date = non_empty_parts[2][:4]
                    service_code = non_empty_parts[2][4:7]
            elif len(non_empty_parts) == 2:
                if len(non_empty_parts[0]) == 3 and non_empty_parts[0].isdigit():
                    expected_cvv = non_empty_parts[0]
                    rest = non_empty_parts[1]
                    pan = rest[:-7]
                    exp_date = rest[-7:-3]
                    service_code = rest[-3:]
                elif len(non_empty_parts[1]) == 3 and non_empty_parts[1].isdigit():
                    rest = non_empty_parts[0]
                    pan = rest[:-7]
                    exp_date = rest[-7:-3]
                    service_code = rest[-3:]
                    expected_cvv = non_empty_parts[1]
                elif len(non_empty_parts[1]) == 7 and non_empty_parts[1].isdigit():
                    expected_cvv = non_empty_parts[0][:3]
                    pan = non_empty_parts[0][3:]
                    exp_date = non_empty_parts[1][:4]
                    service_code = non_empty_parts[1][4:7]
                else:
                    expected_cvv = non_empty_parts[0][:3]
                    pan = non_empty_parts[0][3:]
                    exp_date = non_empty_parts[1][:4] if len(non_empty_parts[1]) >= 4 else ""
                    service_code = non_empty_parts[1][4:7] if len(non_empty_parts[1]) >= 7 else ""
            else:
                expected_cvv = non_empty_parts[0][:3] if non_empty_parts else ""
                pan = non_empty_parts[0][3:] if non_empty_parts else ""
                exp_date = ""
                service_code = ""
        elif "=" in rem:
            expected_cvv = rem[:3]
            track2 = rem[3:]
            if "=" in track2:
                pan, rest = track2.split("=", 1)
                exp_date = rest[:4]
                service_code = rest[4:7]
            else:
                pan, rest = rem.split("=", 1)
                exp_date = rest[:4]
                service_code = rest[4:7]
        else:
            expected_cvv = rem[:3]
            rem_rest = rem[3:]
            pan = rem_rest[:-7]
            exp_date = rem_rest[-7:-3]
            service_code = rem_rest[-3:]

        pan = "".join([c for c in pan if c.isdigit()])
        exp_date = "".join([c for c in exp_date if c.isdigit()])[:4]
        service_code = "".join([c for c in service_code if c.isdigit()])[:3]
        expected_cvv = "".join([c for c in expected_cvv if c.isdigit()])[:3]

        cvk_raw = _decrypt_cvk(self.hsm, cvk_str)

        calculated_cvv = calculate_cvv(cvk_raw, pan, exp_date, service_code)
        if calculated_cvv == expected_cvv:
            return ErrorCodes.SUCCESS, b""
        else:
            return ErrorCodes.LMK_ERROR, b""
