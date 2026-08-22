"""
PIN Processing Command Handlers: CA/CB, DC/DD, EC/ED, BA/BB, EE/EF.
"""

import os
import random
from binascii import hexlify, unhexlify
from typing import Tuple, Optional

import Crypto.Cipher.DES3
import Crypto.Cipher.AES
from pythales.crypto.tools import get_visa_pvv
from pythales.commands.base import BaseCommandHandler
from pythales.commands.key_mgmt import _extract_key_string
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock


def _decrypt_key(hsm, key_str: str, variant: int = 2) -> bytes:
    if not key_str:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Empty key string")
    scheme = key_str[0].upper()
    if scheme == "S":
        _, clear_key = TR31KeyBlock.unwrap(key_str, hsm.LMK)
        return clear_key
    elif scheme in ("U", "X"):
        enc_bytes = unhexlify(key_str[1:])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=variant)
    elif scheme in ("T", "Y"):
        enc_bytes = unhexlify(key_str[1:49])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=variant)
    elif scheme in ("Z", "D", "E", "A"):
        enc_bytes = unhexlify(key_str[1:])
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=variant)
    else:
        enc_bytes = unhexlify(key_str)
        return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=variant)


def decrypt_pin_block(key_bytes: bytes, enc_pin_block_hex: str, format_code: str, account_number: str) -> str:
    """
    Decrypts an encrypted PIN block (format '01' or '48') and returns clear PIN string.
    """
    if len(key_bytes) == 8:
        key_bytes = key_bytes * 2
    fmt = str(format_code).zfill(2)
    if fmt == "01":  # Format 0 (ANSI X9.8 / ISO 9564-1 Format 0)
        if len(enc_pin_block_hex) < 16:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "PIN block too short for Format 0")
        try:
            enc_bytes = unhexlify(enc_pin_block_hex[:16])
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in PIN block")

        cipher = Crypto.Cipher.DES3.new(key_bytes, Crypto.Cipher.DES3.MODE_ECB)
        clear_block_bytes = cipher.decrypt(enc_bytes)

        acct_str = account_number
        if len(acct_str) >= 13:
            acct_12 = acct_str[-13:-1]
        else:
            acct_12 = acct_str.rjust(12, "0")[-12:]
        acct_block_hex = "0000" + acct_12
        try:
            acct_bytes = unhexlify(acct_block_hex)
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in PIN block or account number")

        plain_block_bytes = bytes(a ^ b for a, b in zip(clear_block_bytes, acct_bytes))
        plain_block_hex = hexlify(plain_block_bytes).decode("ascii").upper()

        if plain_block_hex[0] != "0":
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid Format 0 PIN block header")
        pin_len = int(plain_block_hex[1], 16)
        if pin_len < 4 or pin_len > 12:
            raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length {pin_len}")

        pin = plain_block_hex[2:2 + pin_len]
        if not pin.isdigit():
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "PIN contains non-numeric digits")
        return pin

    elif fmt in ("48", "04"):  # Format 4 (ISO 9564-1 Format 4 AES)
        if len(enc_pin_block_hex) < 32:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "PIN block too short for Format 4")
        try:
            enc_bytes = unhexlify(enc_pin_block_hex[:32])
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in Format 4 PIN block")

        k_bytes = key_bytes
        if len(k_bytes) not in (16, 24, 32):
            k_bytes = (k_bytes * 2)[:16]
        c1 = Crypto.Cipher.AES.new(k_bytes, Crypto.Cipher.AES.MODE_ECB)
        inter_bytes = c1.decrypt(enc_bytes)

        acct_str = account_number
        if len(acct_str) >= 12:
            pan_len_indicator = hex(min(15, len(acct_str) - 12))[2:].upper()
            block2_hex = ("4" + pan_len_indicator + acct_str).ljust(32, "0")[:32]
        else:
            block2_hex = ("40" + acct_str.rjust(12, "0")).ljust(32, "0")[:32]

        try:
            block2_bytes = unhexlify(block2_hex)
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in PIN block or account number")
        block1_bytes = bytes(a ^ b for a, b in zip(inter_bytes, block2_bytes))
        block1_hex = hexlify(block1_bytes).decode("ascii").upper()

        if block1_hex[0] != "4":
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid Format 4 PIN block header")
        pin_len = int(block1_hex[1], 16)
        if pin_len < 4 or pin_len > 12:
            raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length {pin_len}")

        pin = block1_hex[2:2 + pin_len]
        if not pin.isdigit():
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "PIN contains non-numeric digits")
        return pin
    else:
        raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK_FORMAT, f"Unsupported PIN block format: '{fmt}'")


def encrypt_pin_block(key_bytes: bytes, pin: str, format_code: str, account_number: str) -> str:
    """
    Encrypts clear PIN into PIN block (format '01' or '48').
    """
    if len(key_bytes) == 8:
        key_bytes = key_bytes * 2
    fmt = str(format_code).zfill(2)
    pin_len = len(pin)
    if pin_len < 4 or pin_len > 12:
        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length {pin_len}")

    if fmt == "01":
        block1_hex = ("0" + hex(pin_len)[2:].upper() + pin).ljust(16, "F")[:16]
        acct_str = account_number
        if len(acct_str) >= 13:
            acct_12 = acct_str[-13:-1]
        else:
            acct_12 = acct_str.rjust(12, "0")[-12:]
        block2_hex = "0000" + acct_12

        try:
            inter_bytes = bytes(a ^ b for a, b in zip(unhexlify(block1_hex), unhexlify(block2_hex)))
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in account number or PIN block")
        cipher = Crypto.Cipher.DES3.new(key_bytes, Crypto.Cipher.DES3.MODE_ECB)
        enc_bytes = cipher.encrypt(inter_bytes)
        return hexlify(enc_bytes).decode("ascii").upper()

    elif fmt in ("48", "04"):
        block1_hex = ("4" + hex(pin_len)[2:].upper() + pin).ljust(32, "F")[:32]
        acct_str = account_number
        if len(acct_str) >= 12:
            pan_len_indicator = hex(min(15, len(acct_str) - 12))[2:].upper()
            block2_hex = ("4" + pan_len_indicator + acct_str).ljust(32, "0")[:32]
        else:
            block2_hex = ("40" + acct_str.rjust(12, "0")).ljust(32, "0")[:32]

        try:
            inter_bytes = bytes(a ^ b for a, b in zip(unhexlify(block1_hex), unhexlify(block2_hex)))
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in account number or PIN block")
        k_bytes = key_bytes
        if len(k_bytes) not in (16, 24, 32):
            k_bytes = (k_bytes * 2)[:16]
        c1 = Crypto.Cipher.AES.new(k_bytes, Crypto.Cipher.AES.MODE_ECB)
        enc_bytes = c1.encrypt(inter_bytes)
        return hexlify(enc_bytes).decode("ascii").upper()
    else:
        raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK_FORMAT, f"Unsupported PIN block format: '{fmt}'")


def _is_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789ABCDEFabcdef" for c in s)


def _is_luhn_valid(s: str) -> bool:
    if not s or not s.isdigit():
        return False
    digits = [int(c) for c in s]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d2 = d * 2
            checksum += d2 - 9 if d2 > 9 else d2
        else:
            checksum += d
    return checksum % 10 == 0


def _extract_pin_block_and_fmt(rem: str) -> Tuple[str, str, str]:
    """
    Extracts pin_block, fmt_code, and remaining payload from rem string.
    Distinguishes 16-character (DES) and 32-character (AES Format 4) PIN blocks cleanly.
    """
    if len(rem) >= 46 and rem[32:34] in ("04", "48", "06") and _is_hex(rem[:32]) and len(rem[34:]) >= 12:
        return rem[:32], rem[32:34], rem[34:]

    if len(rem) >= 18 and rem[16:18] in ("01", "02", "03", "05", "99") and _is_hex(rem[:16]):
        return rem[:16], rem[16:18], rem[18:]

    if len(rem) >= 34 and rem[32:34] in ("04", "48", "06") and _is_hex(rem[:32]):
        return rem[:32], rem[32:34], rem[34:]

    if len(rem) >= 16 and _is_hex(rem[:16]):
        return rem[:16], "01", rem[16:]
    elif len(rem) >= 16:
        raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid or non-hex PIN block")
    else:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Payload too short for PIN block")


def _parse_pan_and_pvv(rem: str) -> Tuple[str, str, str]:
    """
    Parses account_number (PAN), pvki, and pvv_expected from rem.
    PAN can be 12 to 19 digits.
    """
    if ";" in rem:
        track2_or_pan, pvv_part = rem.split(";", 1)
        if "=" in track2_or_pan:
            account_number = track2_or_pan.split("=")[0]
        else:
            account_number = track2_or_pan
        pvki = pvv_part[0] if pvv_part else "1"
        pvv_expected = pvv_part[1:5] if len(pvv_part) >= 5 else pvv_part[1:]
        return account_number, pvki, pvv_expected

    if "=" in rem:
        account_number, rest = rem.split("=", 1)
        pvki = rest[-5] if len(rest) >= 5 else (rest[0] if rest else "1")
        pvv_expected = rest[-4:] if len(rest) >= 5 else (rest[1:] if len(rest) > 1 else "")
        return account_number, pvki, pvv_expected

    delimiter_pos = -1
    for i, ch in enumerate(rem):
        if not ch.isdigit() and ch not in ("A", "B", "C", "D", "E", "F"):
            delimiter_pos = i
            break
    if delimiter_pos != -1:
        account_number = rem[:delimiter_pos]
        rest = rem[delimiter_pos + 1:]
        pvki = rest[0] if rest else "1"
        pvv_expected = rest[1:5] if len(rest) >= 5 else rest[1:]
        return account_number, pvki, pvv_expected

    if len(rem) >= 17:
        account_number = rem[:-5]
        pvki = rem[-5]
        pvv_expected = rem[-4:]
    elif len(rem) == 13:
        account_number = rem[:12]
        pvki = rem[12]
        pvv_expected = ""
    else:
        account_number = rem
        pvki = "1"
        pvv_expected = ""

    return account_number, pvki, pvv_expected


@global_router.register("CA")
class CAHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        CA Translate PIN Block Handler (ZPK1 to ZPK2).
        Supports PIN block format '01' (ISO Format 0) and format '48' (ISO Format 4).
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 30:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "CA payload too short")

        src_zpk_str, rem = _extract_key_string(payload_str)
        dst_zpk_str, rem = _extract_key_string(rem)

        max_pin_len_str = rem[:2]
        rem = rem[2:]

        src_pin_block, src_fmt, rem = _extract_pin_block_and_fmt(rem)
        known_valid_formats = ("01", "02", "03", "04", "05", "48", "99")
        cand_fmt = rem[:2] if len(rem) >= 2 else ""
        cand_pan = rem[2:] if len(rem) >= 2 else ""

        if cand_fmt in known_valid_formats:
            if cand_fmt == "48" and cand_pan.startswith("0"):
                dst_fmt = src_fmt
                account_number = rem
            elif 12 <= len(cand_pan) <= 19 and cand_pan.isdigit():
                dst_fmt = cand_fmt
                account_number = cand_pan
            else:
                dst_fmt = src_fmt
                account_number = rem
        else:
            dst_fmt = src_fmt
            account_number = rem

        src_zpk_bytes = _decrypt_key(self.hsm, src_zpk_str, variant=2)
        dst_zpk_bytes = _decrypt_key(self.hsm, dst_zpk_str, variant=2)

        clear_pin = decrypt_pin_block(src_zpk_bytes, src_pin_block, src_fmt, account_number)

        if max_pin_len_str.isdigit():
            max_len = int(max_pin_len_str)
            if len(clear_pin) > max_len:
                raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"PIN length {len(clear_pin)} exceeds max {max_len}")

        dst_pin_block = encrypt_pin_block(dst_zpk_bytes, clear_pin, dst_fmt, account_number)
        resp_payload = (dst_pin_block + dst_fmt).encode("ascii")
        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("DC")
class DCHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        DC Verify Customer PIN Handler.
        Supports PIN block format '01' and format '48'.
        Returns 'DD' error '00' on success or '01' on mismatch.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 30:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "DC payload too short")

        tpk_str, rem = _extract_key_string(payload_str)
        pvk_str, rem = _extract_key_string(rem)

        pin_block, fmt_code, rem = _extract_pin_block_and_fmt(rem)
        account_number, pvki, pvv_expected = _parse_pan_and_pvv(rem)

        tpk_bytes = _decrypt_key(self.hsm, tpk_str, variant=2)
        pvk_bytes = _decrypt_key(self.hsm, pvk_str, variant=3)

        try:
            clear_pin = decrypt_pin_block(tpk_bytes, pin_block, fmt_code, account_number)
        except PayShieldException:
            raise
        except Exception:
            return ErrorCodes.LMK_ERROR, b""  # '01' mismatch / decrypt failure

        if len(pvk_bytes) < 16:
            pvk_bytes = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex = hexlify(pvk_bytes[:16]).decode("ascii").upper()

        pan_for_pvv = account_number if len(account_number) >= 12 else account_number.rjust(12, "0")
        try:
            calc_pvv_bytes = get_visa_pvv(
                pan_for_pvv.encode("ascii"),
                pvki.encode("ascii"),
                clear_pin[:4].encode("ascii"),
                pvk_hex.encode("ascii")
            )
            calc_pvv = calc_pvv_bytes.decode("ascii")
        except Exception:
            return ErrorCodes.LMK_ERROR, b""

        if calc_pvv == pvv_expected or not pvv_expected:
            return ErrorCodes.SUCCESS, b""
        else:
            return ErrorCodes.LMK_ERROR, b""  # '01' failure


@global_router.register("EC")
class ECHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        EC Translate PIN Block under LMK / Verify Interchange PIN Handler.
        Supports format '01' and format '48'.
        Returns response code 'ED', error '00' on success or '01' on failure.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 30:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "EC payload too short")

        zpk_str, rem = _extract_key_string(payload_str)
        pvk_str, rem = _extract_key_string(rem)

        pin_block, fmt_code, rem = _extract_pin_block_and_fmt(rem)
        account_number, pvki, pvv_expected = _parse_pan_and_pvv(rem)

        zpk_bytes = _decrypt_key(self.hsm, zpk_str, variant=2)
        pvk_bytes = _decrypt_key(self.hsm, pvk_str, variant=3)

        try:
            clear_pin = decrypt_pin_block(zpk_bytes, pin_block, fmt_code, account_number)
        except PayShieldException:
            raise
        except Exception:
            return ErrorCodes.LMK_ERROR, b""

        if pvv_expected:
            if len(pvk_bytes) < 16:
                pvk_bytes = (pvk_bytes + pvk_bytes)[:16]
            pvk_hex = hexlify(pvk_bytes[:16]).decode("ascii").upper()

            pan_for_pvv = account_number if len(account_number) >= 12 else account_number.rjust(12, "0")
            try:
                calc_pvv_bytes = get_visa_pvv(
                    pan_for_pvv.encode("ascii"),
                    pvki.encode("ascii"),
                    clear_pin[:4].encode("ascii"),
                    pvk_hex.encode("ascii")
                )
                calc_pvv = calc_pvv_bytes.decode("ascii")
                if calc_pvv == pvv_expected:
                    return ErrorCodes.SUCCESS, b""
                else:
                    return ErrorCodes.LMK_ERROR, b""
            except Exception:
                return ErrorCodes.LMK_ERROR, b""
        else:
            # If no PVV in request, return PIN block encrypted under LMK
            pin_under_lmk = encrypt_pin_block(self.hsm.LMK, clear_pin, "01", account_number)
            return ErrorCodes.SUCCESS, pin_under_lmk.encode("ascii")


@global_router.register("BA")
class BAHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        BA Generate Random PIN / Encrypt Clear PIN Handler.
        Returns response code 'BB', error '00'.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if not payload_str:
            pin = "".join([str(random.randint(0, 9)) for _ in range(4)])
            return ErrorCodes.SUCCESS, pin.encode("ascii")

        if payload_str[0].upper() in ("U", "T", "S", "X", "Y"):
            zpk_str, rem = _extract_key_string(payload_str)
            
            found_delim = None
            for ch in rem:
                if ch in (";", "F", "f"):
                    found_delim = ch
                    break

            if found_delim is not None:
                parts = rem.split(found_delim, 1)
                account_number = parts[0]
                pin_part = parts[1]
                if pin_part:
                    if not pin_part.isdigit() or not (4 <= len(pin_part) <= 12):
                        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid clear PIN length/content: '{pin_part}'")
                    clear_pin = pin_part
                else:
                    clear_pin = "".join([str(random.randint(0, 9)) for _ in range(4)])
            else:
                if len(rem) == 12:
                    account_number = rem
                    clear_pin = "".join([str(random.randint(0, 9)) for _ in range(4)])
                elif len(rem) == 14:
                    account_number = rem[:12]
                    pin_spec = rem[12:]
                    if pin_spec.isdigit() and (4 <= int(pin_spec) <= 12):
                        clear_pin = "".join([str(random.randint(0, 9)) for _ in range(int(pin_spec))])
                    else:
                        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length specifier '{pin_spec}'")
                elif len(rem) == 16:
                    account_number = rem[:12]
                    clear_pin = rem[12:]
                    if not clear_pin.isdigit() or not (4 <= len(clear_pin) <= 12):
                        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid clear PIN '{clear_pin}'")
                elif len(rem) == 18:
                    account_number = rem[:16]
                    pin_spec = rem[16:]
                    if pin_spec.isdigit() and (4 <= int(pin_spec) <= 12):
                        clear_pin = "".join([str(random.randint(0, 9)) for _ in range(int(pin_spec))])
                    else:
                        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length specifier '{pin_spec}'")
                elif len(rem) >= 20:
                    account_number = rem[:16]
                    pin_part = rem[16:]
                    if not pin_part.isdigit() or not (4 <= len(pin_part) <= 12):
                        raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid clear PIN '{pin_part}'")
                    clear_pin = pin_part
                else:
                    account_number = rem.rjust(12, "0")
                    clear_pin = "".join([str(random.randint(0, 9)) for _ in range(4)])

            zpk_bytes = _decrypt_key(self.hsm, zpk_str, variant=2)
            enc_pin_block = encrypt_pin_block(zpk_bytes, clear_pin, "01", account_number)
            return ErrorCodes.SUCCESS, (clear_pin + enc_pin_block).encode("ascii")
        else:
            pin_len = int(payload_str[:2]) if payload_str[:2].isdigit() else 4
            if pin_len < 4 or pin_len > 12:
                raise PayShieldException(ErrorCodes.PIN_LENGTH_OUT_OF_RANGE, f"Invalid PIN length {pin_len}")
            clear_pin = "".join([str(random.randint(0, 9)) for _ in range(pin_len)])
            return ErrorCodes.SUCCESS, clear_pin.encode("ascii")


@global_router.register("EE")
class EEHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        EE Verify IBM 3624 PIN Offset Handler.
        Returns response code 'EF', error '00' on success or '01' on failure.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 30:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "EE payload too short")

        zpk_str, rem = _extract_key_string(payload_str)
        pvk_str, rem = _extract_key_string(rem)

        pin_block, fmt_code, rem = _extract_pin_block_and_fmt(rem)

        zpk_bytes = _decrypt_key(self.hsm, zpk_str, variant=2)
        pvk_bytes = _decrypt_key(self.hsm, pvk_str, variant=3)

        try:
            if ";" in rem:
                parts = rem.split(";", 1)
                account_number = parts[0]
                rem = parts[1]
                if len(rem) < 16:
                    raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "EE decimalization table incomplete")
                dec_table = rem[:16]
                rem = rem[16:]
                customer_pin = decrypt_pin_block(zpk_bytes, pin_block, fmt_code, account_number)
            else:
                customer_pin = None
                if len(rem) >= 32 and (fmt_code in ("04", "48") or len(rem) in (36, 38, 52, 54)):
                    try:
                        customer_pin = decrypt_pin_block(zpk_bytes, pin_block, fmt_code, rem[:16])
                        account_number = rem[:16]
                        rem = rem[16:]
                    except PayShieldException:
                        customer_pin = None
                if customer_pin is None:
                    customer_pin = decrypt_pin_block(zpk_bytes, pin_block, fmt_code, rem[:12])
                    account_number = rem[:12]
                    rem = rem[12:]

                if len(rem) < 16:
                    raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "EE decimalization table incomplete")
                dec_table = rem[:16]
                rem = rem[16:]
        except PayShieldException as exc:
            if exc.error_code == ErrorCodes.INVALID_INPUT_DATA:
                raise
            return exc.error_code, b""

        pin_len = len(customer_pin)

        if len(rem) >= pin_len + 16:
            offset = rem[:pin_len]
            validation_data = rem[pin_len:pin_len + 16]
        elif len(rem) >= pin_len:
            offset = rem[:pin_len]
            validation_data = account_number.rjust(16, "0")
        elif len(rem) >= 16:
            offset = rem[:-16]
            validation_data = rem[-16:]
        else:
            offset = rem[:pin_len] if len(rem) >= pin_len else rem.rjust(pin_len, "0")
            validation_data = account_number.rjust(16, "0")

        try:
            val_bytes = unhexlify(validation_data[:16])
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_PIN_BLOCK, "Invalid hex in validation data")

        if len(pvk_bytes) < 16:
            pvk_bytes = (pvk_bytes * 2)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)

        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin_chars = []
        for c in enc_val_hex:
            val = int(c, 16)
            if val < len(dec_table):
                natural_pin_chars.append(dec_table[val])
        natural_pin = "".join(natural_pin_chars)[:pin_len]

        if len(natural_pin) < pin_len:
            natural_pin = natural_pin.ljust(pin_len, "0")

        expected_pin = ""
        for i in range(pin_len):
            nat_d = int(natural_pin[i]) if natural_pin[i].isdigit() else 0
            off_d = int(offset[i]) if i < len(offset) and offset[i].isdigit() else 0
            expected_pin += str((nat_d + off_d) % 10)

        if customer_pin == expected_pin:
            return ErrorCodes.SUCCESS, b""
        else:
            return ErrorCodes.LMK_ERROR, b""
