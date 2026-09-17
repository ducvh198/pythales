"""
Data Protection & MAC Command Handlers:
- M0/M1 (Encrypt Data)
- M2/M3 (Decrypt Data)
- M4/M5 (Translate Data Block)
- M6/M7 (Generate MAC)
- M8/M9 (Verify MAC)
"""

import os
import math
import string
import hmac
import hashlib
from binascii import hexlify, unhexlify
from typing import Tuple, Optional
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import Crypto.Cipher.AES

from pythales.commands.base import BaseCommandHandler
from pythales.commands.key_mgmt import _extract_key_string, _parse_key_payload, KEY_TYPE_VARIANTS
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


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


def parse_mode_and_datalen(rem: str) -> Tuple[str, int, str]:
    """
    Disambiguates 1-char vs 2-char mode in M0/M2/M4/M6/M8 commands.
    Returns (mode, data_len_bytes, remaining_str_after_datalen).
    """
    if len(rem) >= 6:
        mode2 = rem[:2]
        if mode2 in ("00", "01", "06", "11", "02", "03"):
            try:
                data_len2 = int(rem[2:6], 16)
                rem_data2 = rem[6:]
                if len(rem_data2) == data_len2 * 2 or len(rem_data2) == data_len2 or \
                   len(rem_data2) >= data_len2 * 2 + 16 or len(rem_data2) >= data_len2 + 16:
                    return mode2, data_len2, rem_data2
            except ValueError:
                pass

    if len(rem) >= 5:
        mode1 = rem[0]
        try:
            data_len1 = int(rem[1:5], 16)
            rem_data1 = rem[5:]
            return mode1, data_len1, rem_data1
        except ValueError:
            pass

    raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid mode or data length field")


def parse_payload_data_and_rem(rem: str, data_len: int, has_suffix_16: bool = False) -> Tuple[bytes, str]:
    """
    Unambiguously extracts data_bytes and remaining string from rem.
    Checks exact payload signature lengths to distinguish ASCII vs HEX data and trailing 16-hex fields (IV/ARQC/MAC).
    Signature lengths:
    - len(rem) == data_len * 2 + 16 (hex data + 16-hex IV/suffix)
    - len(rem) == data_len + 16 (ASCII data + 16-hex IV/suffix)
    - len(rem) == data_len * 2 (hex data without suffix)
    - len(rem) == data_len (ASCII data without suffix)
    """
    hex_len = data_len * 2
    ascii_len = data_len
    total_len = len(rem)

    is_hex_chars = total_len >= hex_len and all(c in "0123456789ABCDEFabcdef" for c in rem[:hex_len])

    if has_suffix_16:
        if total_len >= hex_len + 16 and is_hex_chars and total_len != ascii_len + 16:
            return unhexlify(rem[:hex_len]), rem[hex_len:]
        elif total_len >= ascii_len + 16:
            return rem[:ascii_len].encode("ascii"), rem[ascii_len:]
        elif total_len == hex_len and is_hex_chars:
            return unhexlify(rem[:hex_len]), rem[hex_len:]
        elif total_len == ascii_len:
            return rem[:ascii_len].encode("ascii"), rem[ascii_len:]
    else:
        if total_len == hex_len and is_hex_chars:
            return unhexlify(rem[:hex_len]), rem[hex_len:]
        elif total_len == ascii_len:
            return rem[:ascii_len].encode("ascii"), rem[ascii_len:]
        elif total_len >= hex_len and is_hex_chars:
            return unhexlify(rem[:hex_len]), rem[hex_len:]

    if is_hex_chars and total_len >= hex_len:
        return unhexlify(rem[:hex_len]), rem[hex_len:]

    return rem[:ascii_len].encode("ascii"), rem[ascii_len:]


def parse_m4_modes(rem: str) -> Tuple[str, str, str]:
    """
    Unambiguously parses (src_mode, tgt_mode, rest_str) from M4 payload.
    Disambiguates 1-char vs 2-char modes by evaluating structural payload candidate matches.
    """
    valid_2char = ("00", "01", "06", "11")
    valid_1char = ("0", "1", "6")

    candidates = []
    if len(rem) >= 8 and rem[:2] in valid_2char and rem[2:4] in valid_2char:
        candidates.append((rem[:2], rem[2:4], 4))
    if len(rem) >= 7 and rem[:2] in valid_2char and rem[2] in valid_1char:
        candidates.append((rem[:2], rem[2], 3))
    if len(rem) >= 7 and rem[0] in valid_1char and rem[1:3] in valid_2char:
        candidates.append((rem[0], rem[1:3], 3))
    if len(rem) >= 6 and rem[0] in valid_1char and rem[1] in valid_1char:
        candidates.append((rem[0], rem[1], 2))

    for src_mode, tgt_mode, mode_len in candidates:
        rest = rem[mode_len:]
        try:
            data_len = int(rest[:4], 16)
        except ValueError:
            continue
        after_datalen = rest[4:]
        src_iv_len = 16 if src_mode in ("01", "1", "06", "6") else 0
        tgt_iv_len = 16 if tgt_mode in ("01", "1", "06", "6") else 0
        expected_len1 = data_len * 2 + src_iv_len + tgt_iv_len
        expected_len2 = data_len * 2 + 32 if (src_iv_len > 0 or tgt_iv_len > 0) else data_len * 2
        if len(after_datalen) == expected_len1 or len(after_datalen) == expected_len2:
            return src_mode, tgt_mode, rest

    for src_mode, tgt_mode, mode_len in candidates:
        rest = rem[mode_len:]
        try:
            int(rest[:4], 16)
            return src_mode, tgt_mode, rest
        except ValueError:
            continue

    raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid M4 source or target mode")


def _get_key_raw(hsm, key_str: str, default_variant: int = 8) -> bytes:
    """Helper to extract raw key bytes from key string under LMK or TR-31 Key Block."""
    if key_str.startswith("S"):
        _, raw_key = TR31KeyBlock.unwrap(key_str, hsm.LMK)
        return raw_key
    scheme, enc_bytes = _parse_key_payload(key_str)
    return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=default_variant)


def _get_des_cipher(key: bytes, mode, iv: Optional[bytes] = None, segment_size: Optional[int] = None):
    """
    Return DES or DES3 cipher object appropriately.
    Handles single DES (8 bytes), double DES (16 bytes), triple DES (24 bytes),
    and degenerate keys without throwing ValueError in PyCryptodome.
    """
    kwargs = {}
    if iv is not None:
        kwargs["iv"] = iv
    if segment_size is not None:
        kwargs["segment_size"] = segment_size

    if len(key) == 8:
        return Crypto.Cipher.DES.new(key, mode, **kwargs)
    elif len(key) == 16:
        if key[:8] == key[8:]:
            return Crypto.Cipher.DES.new(key[:8], mode, **kwargs)
        return Crypto.Cipher.DES3.new(key + key[:8], mode, **kwargs)
    else:
        if key[:8] == key[8:16] == key[16:]:
            return Crypto.Cipher.DES.new(key[:8], mode, **kwargs)
        elif key[:8] == key[8:16]:
            return Crypto.Cipher.DES.new(key[16:], mode, **kwargs)
        elif key[8:16] == key[16:]:
            return Crypto.Cipher.DES.new(key[:8], mode, **kwargs)
        return Crypto.Cipher.DES3.new(key, mode, **kwargs)


def des3_ctr_crypt(key: bytes, data: bytes, iv_bytes: bytes, offset: int = 0, length: int = 64) -> bytes:
    """CTR mode stream encryption/decryption using 3DES/DES."""
    block_size = 8
    iv_int = int.from_bytes(iv_bytes, "big")
    mask = ((1 << length) - 1) << offset
    counter_val = (iv_int >> offset) & ((1 << length) - 1)
    iv_base = iv_int & ~mask
    cipher_ecb = _get_des_cipher(key, Crypto.Cipher.DES.MODE_ECB if len(key) == 8 else Crypto.Cipher.DES3.MODE_ECB)
    output = bytearray()
    num_blocks = (len(data) + block_size - 1) // block_size
    for i in range(num_blocks):
        current_counter = (counter_val + i) % (1 << length)
        block_iv_int = iv_base | (current_counter << offset)
        counter_block = block_iv_int.to_bytes(block_size, "big")
        keystream = cipher_ecb.encrypt(counter_block)
        chunk = data[i * block_size : (i + 1) * block_size]
        output.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
    return bytes(output)


def aes_ctr_crypt(key: bytes, data: bytes, iv_bytes: bytes, offset: int = 0, length: int = 128) -> bytes:
    """CTR mode stream encryption/decryption using AES."""
    block_size = 16
    iv_int = int.from_bytes(iv_bytes, "big")
    mask = ((1 << length) - 1) << offset
    counter_val = (iv_int >> offset) & ((1 << length) - 1)
    iv_base = iv_int & ~mask
    cipher_ecb = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    output = bytearray()
    num_blocks = (len(data) + block_size - 1) // block_size
    for i in range(num_blocks):
        current_counter = (counter_val + i) % (1 << length)
        block_iv_int = iv_base | (current_counter << offset)
        counter_block = block_iv_int.to_bytes(block_size, "big")
        keystream = cipher_ecb.encrypt(counter_block)
        chunk = data[i * block_size : (i + 1) * block_size]
        output.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
    return bytes(output)


def calc_ctr_output_iv(iv_bytes: bytes, data_len: int, block_size: int, offset: int, length: int) -> bytes:
    """Calculate updated counter IV after processing data_len bytes."""
    num_blocks = (data_len + block_size - 1) // block_size
    iv_int = int.from_bytes(iv_bytes, "big")
    mask = ((1 << length) - 1) << offset
    counter_val = (iv_int >> offset) & ((1 << length) - 1)
    iv_base = iv_int & ~mask
    next_counter = (counter_val + num_blocks) % (1 << length)
    return (iv_base | (next_counter << offset)).to_bytes(block_size, "big")


def _ofb_crypt(key: bytes, data: bytes, iv: bytes, key_alg: str) -> Tuple[bytes, bytes]:
    """OFB mode stream encryption/decryption and chaining IV calculation."""
    block_size = 16 if key_alg == "A" else 8
    if key_alg == "A":
        cipher_ecb = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    else:
        cipher_ecb = _get_des_cipher(key, Crypto.Cipher.DES.MODE_ECB if len(key) == 8 else Crypto.Cipher.DES3.MODE_ECB)
    output = bytearray()
    cur_iv = iv
    num_blocks = (len(data) + block_size - 1) // block_size
    for i in range(num_blocks):
        cur_iv = cipher_ecb.encrypt(cur_iv)
        chunk = data[i * block_size : (i + 1) * block_size]
        output.extend(bytes(a ^ b for a, b in zip(chunk, cur_iv)))
    return bytes(output), cur_iv


def _is_exact_wire_format(payload: bytes) -> bool:
    """Detect whether payload follows standard payShield 10K wire layout."""
    if len(payload) < 4:
        return False
    # Legacy payloads start with key scheme prefix (U, T, S, R, X, Y)
    if chr(payload[0]).upper() in ("U", "T", "S", "R", "X", "Y"):
        return False
    # If starting with FF1 / BPS mode: Mode (10 or 11) + Radix Flag ('A' or 'U')
    if payload[:2] in (b"10", b"11") and len(payload) >= 3 and payload[2:3].upper() in (b"A", b"U"):
        return True
    # Key Type at offset 4..7
    if len(payload) >= 7:
        kt = payload[4:7].decode("ascii", errors="ignore").upper()
        if kt in ("00A", "00B", "30B", "FFF", "009", "609", "809", "909"):
            return True
    # Standard format: Mode + InFmt + OutFmt
    if payload[:2] in (b"00", b"01", b"02", b"03", b"04", b"05", b"06", b"10", b"11", b"13"):
        if payload[2:3] in (b"0", b"1", b"2") and payload[3:4] in (b"0", b"1", b"2"):
            return True
    if len(payload) >= 7 and payload[2:3] in (b"0", b"1", b"2") and payload[3:4] in (b"0", b"1", b"2"):
        kt = payload[4:7].decode("ascii", errors="ignore").upper()
        if kt in ("00A", "00B", "30B", "FFF", "009", "609", "809", "909"):
            return True
    return False


def _read_ascii(payload: bytes, pos: int, length: int, error_code: str, name: str) -> Tuple[str, int]:
    if len(payload) < pos + length:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Missing {name}")
    try:
        return payload[pos:pos + length].decode("ascii"), pos + length
    except UnicodeDecodeError as exc:
        raise PayShieldException(error_code, f"Invalid {name}") from exc


def _parse_exact_m0_m2(hsm, payload: bytes, decrypt: bool = False):
    """Parse the Core Guide M0/M2 wire layout for the implemented modes."""
    pos = 0
    mode, pos = _read_ascii(payload, pos, 2, ErrorCodes.INVALID_MODE, "Mode Flag")
    if mode in ("04", "13"):
        raise PayShieldException(ErrorCodes.COMMAND_NOT_LICENSED, "Visa encryption requires license PS10-LIC-VDSP")
    if mode not in ("00", "01", "02", "03", "05", "06", "10", "11"):
        raise PayShieldException(ErrorCodes.INVALID_MODE, f"Unsupported Mode Flag '{mode}'")

    radix = None
    tweak = b""
    if mode in ("10", "11"):
        radix_flag, pos = _read_ascii(payload, pos, 1, ErrorCodes.INVALID_INPUT_DATA, "FPE Radix Flag")
        if radix_flag == "A":
            radix = 10
        elif radix_flag == "U":
            radix_len = 3 if mode == "10" else 5
            radix_text, pos = _read_ascii(payload, pos, radix_len, ErrorCodes.INVALID_INPUT_DATA, "FPE Radix Value")
            if not radix_text.isdigit() or not 2 <= int(radix_text) <= 256:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "FPE radix must be 00002..00256")
            radix = int(radix_text)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid FPE Radix Flag")

        if mode == "10":
            if len(payload) < pos + 8:
                raise PayShieldException(ErrorCodes.DATA_LENGTH_ERROR, "BPS Tweak is shorter than declared")
            tweak = payload[pos:pos + 8]
            pos += 8
        else:
            tweak_len_text, pos = _read_ascii(payload, pos, 4, ErrorCodes.INVALID_INPUT_DATA, "FPE Tweak Length")
            try:
                tweak_len = int(tweak_len_text, 16)
            except ValueError as exc:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid FPE Tweak Length") from exc
            if len(payload) < pos + tweak_len:
                raise PayShieldException(ErrorCodes.DATA_LENGTH_ERROR, "FPE Tweak is shorter than declared")
            tweak = payload[pos:pos + tweak_len]
            pos += tweak_len

    input_format, pos = _read_ascii(payload, pos, 1, ErrorCodes.INVALID_INPUT_FORMAT, "Input Format Flag")
    valid_input = ("0", "1") if decrypt else ("0", "1", "2")
    if input_format not in valid_input:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_FORMAT, "Invalid Input Format Flag")
    output_format, pos = _read_ascii(payload, pos, 1, ErrorCodes.INVALID_OUTPUT_FORMAT, "Output Format Flag")
    valid_output = ("0", "1", "2") if decrypt else ("0", "1")
    if output_format not in valid_output:
        raise PayShieldException(ErrorCodes.INVALID_OUTPUT_FORMAT, "Invalid Output Format Flag")

    key_type, pos = _read_ascii(payload, pos, 3, ErrorCodes.INVALID_COMMAND_KEY_TYPE, "Key Type")
    if key_type not in ("00A", "00B", "30B", "FFF", "009", "609", "809", "909"):
        raise PayShieldException(ErrorCodes.INVALID_COMMAND_KEY_TYPE, f"Invalid M0/M2 Key Type '{key_type}'")

    if len(payload) <= pos:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing Key")
    scheme = chr(payload[pos]).upper()
    variant = KEY_TYPE_VARIANTS.get(key_type, 8)

    if scheme in ("U", "X"):
        key_field_len = 33
        key_field, pos = _read_ascii(payload, pos, key_field_len, ErrorCodes.INVALID_INPUT_DATA, "Key")
        try:
            encrypted_key = unhexlify(key_field[1:])
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Key contains non-hex data") from exc
        key_raw = hsm.lmk_engine.decrypt_under_lmk(encrypted_key, variant=variant)
        key_alg = "T"
    elif scheme in ("T", "Y"):
        key_field_len = 49
        key_field, pos = _read_ascii(payload, pos, key_field_len, ErrorCodes.INVALID_INPUT_DATA, "Key")
        try:
            encrypted_key = unhexlify(key_field[1:])
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Key contains non-hex data") from exc
        key_raw = hsm.lmk_engine.decrypt_under_lmk(encrypted_key, variant=variant)
        key_alg = "T"
    elif scheme == "Z":
        key_field_len = 17
        key_field, pos = _read_ascii(payload, pos, key_field_len, ErrorCodes.INVALID_INPUT_DATA, "Key")
        try:
            encrypted_key = unhexlify(key_field[1:])
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Key contains non-hex data") from exc
        key_raw = hsm.lmk_engine.decrypt_under_lmk(encrypted_key, variant=variant)
        key_alg = "T"
    elif scheme in ("S", "R"):
        if len(payload) < pos + 6:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "TR-31 header too short")
        block_len_str = payload[pos + 2 : pos + 6].decode("ascii", errors="ignore")
        if not block_len_str.isdigit():
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, f"Invalid TR-31 block length '{block_len_str}'")
        key_field_len = 1 + int(block_len_str)
        key_field, pos = _read_ascii(payload, pos, key_field_len, ErrorCodes.INVALID_INPUT_DATA, "Key")
        hdr, key_raw = TR31KeyBlock.unwrap(key_field, hsm.LMK)
        key_alg = hdr.algorithm.upper()
    elif all(chr(c) in "0123456789ABCDEFabcdef" for c in payload[pos : pos + 16]):
        key_field_len = 16
        key_field, pos = _read_ascii(payload, pos, key_field_len, ErrorCodes.INVALID_INPUT_DATA, "Key")
        try:
            encrypted_key = unhexlify(key_field)
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Key contains non-hex data") from exc
        key_raw = hsm.lmk_engine.decrypt_under_lmk(encrypted_key, variant=variant)
        key_alg = "T"
    else:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid Key scheme")

    iv = b""
    iv_len = 32 if key_alg == "A" else 16
    if mode in ("01", "02", "03", "05", "06"):
        iv_text, pos = _read_ascii(payload, pos, iv_len, ErrorCodes.INVALID_INPUT_DATA, "IV")
        try:
            iv = unhexlify(iv_text)
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "IV contains non-hex data") from exc

    ofb_mode_flag = "1"
    if mode == "05":
        ofb_mode_flag, pos = _read_ascii(payload, pos, 1, ErrorCodes.INVALID_INPUT_DATA, "OFB Mode Flag")
        if ofb_mode_flag not in ("1", "8"):
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "OFB Mode Flag must be 1 or 8")

    counter_offset = 0
    counter_length = 128 if key_alg == "A" else 64
    if mode == "06":
        counter_offset_str, pos = _read_ascii(payload, pos, 3, ErrorCodes.INVALID_INPUT_DATA, "Counter Offset")
        counter_length_str, pos = _read_ascii(payload, pos, 3, ErrorCodes.INVALID_INPUT_DATA, "Counter Length")
        if not counter_offset_str.isdigit() or not counter_length_str.isdigit():
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Counter Offset and Length must be numeric")
        counter_offset = int(counter_offset_str)
        counter_length = int(counter_length_str)
        if counter_length < 8:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Counter Length must be at least 008")
        max_bits = 128 if key_alg == "A" else 64
        if counter_offset + counter_length > max_bits:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Counter window exceeds IV bits")

    length_text, pos = _read_ascii(payload, pos, 4, ErrorCodes.INVALID_MESSAGE_LENGTH, "Message Length")
    try:
        message_length = int(length_text, 16)
    except ValueError as exc:
        raise PayShieldException(ErrorCodes.INVALID_MESSAGE_LENGTH, "Invalid Message Length") from exc
    if message_length > 0x7D00:
        raise PayShieldException(ErrorCodes.INVALID_MESSAGE_LENGTH, "Message Length exceeds maximum 32000 bytes")
    if message_length == 0:
        raise PayShieldException(ErrorCodes.DATA_LENGTH_ERROR, "Message Length cannot be zero")

    encoded_length = message_length * 2 if input_format == "1" else message_length
    available = len(payload) - pos
    if available < encoded_length:
        raise PayShieldException(ErrorCodes.DATA_LENGTH_ERROR, "Message is shorter than declared")
    message_field = payload[pos:pos + encoded_length]
    pos += encoded_length
    trailing = payload[pos:]
    if trailing and not (trailing.startswith(b"%") and len(trailing) >= 3 and trailing[1:3].isdigit()):
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Message is longer than declared")

    if input_format == "1":
        try:
            message = unhexlify(message_field)
        except ValueError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Message contains non-hex data") from exc
    else:
        message = message_field

    block_size = 16 if key_alg == "A" else 8
    if mode in ("00", "01") and len(message) % block_size:
        raise PayShieldException(ErrorCodes.INVALID_MESSAGE_LENGTH, "Message is not block aligned")
    if mode == "03" and len(message) % 8:
        raise PayShieldException(ErrorCodes.INVALID_MESSAGE_LENGTH, "Message is not block aligned")
    if mode == "06" and key_alg != "A":
        raise PayShieldException(ErrorCodes.MODE_REQUIRES_AES_KEY, "CTR requires an AES key")
    if mode == "11" and (scheme not in ("S", "R") or key_alg != "A"):
        raise PayShieldException(ErrorCodes.MODE_REQUIRES_AES_KB_LMK, "FF1 requires AES Key Block LMK")

    return mode, output_format, key_raw, iv, message, radix, tweak, key_alg, ofb_mode_flag, counter_offset, counter_length


def _format_exact_data_response(output_format: str, data: bytes, iv: bytes = b"") -> bytes:
    if output_format == "0":
        formatted = data
    elif output_format == "1":
        formatted = hexlify(data).upper()
    else:
        try:
            formatted = data.decode("ascii").encode("ascii")
        except UnicodeDecodeError as exc:
            raise PayShieldException(ErrorCodes.INVALID_OUTPUT_FORMAT, "Plaintext output is not ASCII") from exc
    prefix = hexlify(iv).upper() if iv else b""
    return prefix + f"{len(data):04X}".encode("ascii") + formatted


class FF1Cipher:
    """NIST SP 800-38G Format-Preserving Encryption (FF1)."""

    def __init__(self, key: bytes, radix: int = 10, tweak: bytes = b""):
        if len(key) not in (16, 24, 32):
            raise ValueError("FF1 requires a 128-, 192-, or 256-bit AES key")
        if not 2 <= radix <= 36:
            raise ValueError("FF1 radix must be between 2 and 36")

        self.key = bytes(key)
        self.radix = radix
        self.tweak = bytes(tweak)

    def _prf(self, data: bytes) -> bytes:
        if not data or len(data) % 16:
            raise ValueError("FF1 PRF input must contain complete AES blocks")
        cipher = Crypto.Cipher.AES.new(
            self.key, Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16
        )
        return cipher.encrypt(data)[-16:]

    def _validate_text(self, value: str) -> None:
        if len(value) < 2:
            raise ValueError("FF1 input must contain at least two numerals")
        try:
            digits = [int(char, self.radix) for char in value]
        except ValueError as exc:
            raise ValueError("FF1 input contains a numeral outside the radix") from exc
        if any(digit >= self.radix for digit in digits):
            raise ValueError("FF1 input contains a numeral outside the radix")

    def _round_material(self, n: int, u: int, v: int, b: int, d: int,
                        round_number: int, numeral: int) -> int:
        p = (
            bytes((1, 2, 1))
            + self.radix.to_bytes(3, "big")
            + bytes((10, u & 0xFF))
            + n.to_bytes(4, "big")
            + len(self.tweak).to_bytes(4, "big")
        )
        q = (
            self.tweak
            + b"\x00" * ((-len(self.tweak) - b - 1) % 16)
            + bytes((round_number,))
            + numeral.to_bytes(b, "big")
        )
        r = self._prf(p + q)

        s = bytearray(r)
        aes = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_ECB)
        for block_number in range(1, math.ceil(d / 16)):
            counter = block_number.to_bytes(16, "big")
            s.extend(aes.encrypt(bytes(a ^ b for a, b in zip(r, counter))))
        return int.from_bytes(s[:d], "big")

    def _digits_to_int(self, digits) -> int:
        value = 0
        for digit in digits:
            value = value * self.radix + digit
        return value

    def _int_to_digits(self, value: int, length: int):
        digits = [0] * length
        for index in range(length - 1, -1, -1):
            value, digits[index] = divmod(value, self.radix)
        return digits

    def _format_digits(self, digits) -> str:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join(alphabet[digit] for digit in digits)

    def encrypt(self, X: str) -> str:
        self._validate_text(X)
        n = len(X)
        u = n // 2
        v = n - u
        A = [int(c, self.radix) for c in X[:u]]
        B = [int(c, self.radix) for c in X[u:]]

        b = int(math.ceil((v * math.log2(self.radix)) / 8.0))
        d = 4 * math.ceil(b / 4.0) + 4

        for i in range(10):
            m = u if i % 2 == 0 else v
            y = self._round_material(
                n, u, v, b, d, i, self._digits_to_int(B)
            )
            c = (self._digits_to_int(A) + y) % (self.radix ** m)
            C = self._int_to_digits(c, m)

            A = B
            B = C

        return self._format_digits(A + B)

    def decrypt(self, X: str) -> str:
        self._validate_text(X)
        n = len(X)
        u = n // 2
        v = n - u
        A = [int(c, self.radix) for c in X[:u]]
        B = [int(c, self.radix) for c in X[u:]]

        b = int(math.ceil((v * math.log2(self.radix)) / 8.0))
        d = 4 * math.ceil(b / 4.0) + 4

        for i in range(9, -1, -1):
            m = u if i % 2 == 0 else v
            y = self._round_material(
                n, u, v, b, d, i, self._digits_to_int(A)
            )
            c = (self._digits_to_int(B) - y) % (self.radix ** m)
            C = self._int_to_digits(c, m)

            B = A
            A = C

        return self._format_digits(A + B)


def iso9797_alg1_mac(key: bytes, data: bytes) -> bytes:
    """ISO 9797-1 Algorithm 1 CBC-MAC."""
    if len(key) == 16:
        key = key + key[:8]
    pad_len = (8 - (len(data) % 8)) % 8
    padded_data = data + b"\x80" + b"\x00" * (pad_len - 1 if pad_len > 0 else 7)
    cipher = Crypto.Cipher.DES3.new(key, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
    return cipher.encrypt(padded_data)[-8:]


def iso9797_alg3_mac(key: bytes, data: bytes) -> bytes:
    """ISO 9797-1 Algorithm 3 (Retail MAC / ANSI X9.19)."""
    k1 = key[:8]
    k2 = key[8:16] if len(key) >= 16 else key[:8]
    pad_len = (8 - (len(data) % 8)) % 8
    padded_data = data + b"\x80" + b"\x00" * (pad_len - 1 if pad_len > 0 else 7)

    cipher1 = Crypto.Cipher.DES.new(k1, Crypto.Cipher.DES.MODE_CBC, iv=b"\x00" * 8)
    y = cipher1.encrypt(padded_data)[-8:]

    cipher2_dec = Crypto.Cipher.DES.new(k2, Crypto.Cipher.DES.MODE_ECB)
    z = cipher2_dec.decrypt(y)

    cipher1_enc = Crypto.Cipher.DES.new(k1, Crypto.Cipher.DES.MODE_ECB)
    mac = cipher1_enc.encrypt(z)
    return mac


def cmac_calc(key: bytes, data: bytes) -> bytes:
    """NIST SP 800-38B CMAC algorithm."""
    block_size = 8
    if len(key) == 16:
        key_3des = key + key[:8]
    else:
        key_3des = key

    cipher_zero = Crypto.Cipher.DES3.new(key_3des, Crypto.Cipher.DES3.MODE_ECB)
    L = cipher_zero.encrypt(b"\x00" * 8)

    def shift_left(b_arr: bytes) -> Tuple[bytes, int]:
        val = int.from_bytes(b_arr, "big")
        msb = (val >> 63) & 1
        shifted = ((val << 1) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
        return shifted, msb

    K1, msb = shift_left(L)
    if msb:
        K1 = bytes(a ^ b for a, b in zip(K1, b"\x00\x00\x00\x00\x00\x00\x00\x1B"))

    K2, msb = shift_left(K1)
    if msb:
        K2 = bytes(a ^ b for a, b in zip(K2, b"\x00\x00\x00\x00\x00\x00\x00\x1B"))

    n = (len(data) + block_size - 1) // block_size
    if n == 0:
        n = 1

    last_complete = (len(data) != 0) and (len(data) % block_size == 0)
    if last_complete:
        M_last = bytes(a ^ b for a, b in zip(data[-block_size:], K1))
        blocks = [data[i * block_size : (i + 1) * block_size] for i in range(n - 1)] + [M_last]
    else:
        rem_len = len(data) % block_size
        padded_last = data[-(rem_len):] if rem_len > 0 else b""
        padded_last += b"\x80" + b"\x00" * (block_size - rem_len - 1)
        M_last = bytes(a ^ b for a, b in zip(padded_last, K2))
        blocks = [data[i * block_size : (i + 1) * block_size] for i in range(n - 1)] + [M_last]

    cipher_cbc = Crypto.Cipher.DES3.new(key_3des, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
    full_data = b"".join(blocks)
    return cipher_cbc.encrypt(full_data)[-8:]


@global_router.register("M0")
class M0Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M0 Encrypt Data Handler.
        Supports modes: '00'/'0' (ECB), '01'/'1' (CBC), '06'/'6' (CTR), '11' (FF1 FPE).
        """
        if _is_exact_wire_format(payload):
            mode, output_format, dek_raw, iv, message, radix, tweak, key_alg, ofb_flag, c_offset, c_len = _parse_exact_m0_m2(
                self.hsm, payload, decrypt=False
            )
            if key_alg == "A":
                if mode == "00":
                    encrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_ECB).encrypt(message)
                    response_iv = b""
                elif mode == "01":
                    encrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CBC, iv=iv).encrypt(message)
                    response_iv = encrypted[-16:]
                elif mode == "02":
                    encrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CFB, iv=iv, segment_size=8).encrypt(message)
                    response_iv = (iv + encrypted)[-16:]
                elif mode == "03":
                    encrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CFB, iv=iv, segment_size=64).encrypt(message)
                    response_iv = (iv + encrypted)[-16:]
                elif mode == "05":
                    encrypted, response_iv = _ofb_crypt(dek_raw, message, iv, key_alg)
                elif mode == "06":
                    encrypted = aes_ctr_crypt(dek_raw, message, iv, c_offset, c_len)
                    response_iv = b""
                elif mode == "11":
                    ff1 = FF1Cipher(dek_raw, radix=radix, tweak=tweak)
                    encrypted = ff1.encrypt(message.decode("ascii")).encode("ascii")
                    response_iv = b""
                else:
                    raise PayShieldException(ErrorCodes.INVALID_MODE, f"Unsupported mode '{mode}'")
            else:
                if mode == "00":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_ECB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_ECB)
                    encrypted = cipher.encrypt(message)
                    response_iv = b""
                elif mode == "01":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CBC if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CBC, iv=iv)
                    encrypted = cipher.encrypt(message)
                    response_iv = encrypted[-8:]
                elif mode == "02":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CFB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=8)
                    encrypted = cipher.encrypt(message)
                    response_iv = (iv + encrypted)[-8:]
                elif mode == "03":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CFB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=64)
                    encrypted = cipher.encrypt(message)
                    response_iv = (iv + encrypted)[-8:]
                elif mode == "05":
                    encrypted, response_iv = _ofb_crypt(dek_raw, message, iv, key_alg)
                elif mode == "06":
                    encrypted = des3_ctr_crypt(dek_raw, message, iv, c_offset, c_len)
                    response_iv = b""
                elif mode == "11":
                    raise PayShieldException(ErrorCodes.MODE_REQUIRES_AES_KB_LMK, "FF1 requires AES Key Block LMK")
                else:
                    raise PayShieldException(ErrorCodes.INVALID_MODE, f"Unsupported mode '{mode}'")
            return ErrorCodes.SUCCESS, _format_exact_data_response(output_format, encrypted, response_iv)

        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 38:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "M0 payload too short")

        dek_str, rem = _extract_key_string(payload_str)
        is_aes = False
        if dek_str.startswith("S"):
            hdr, dek_raw = TR31KeyBlock.unwrap(dek_str, self.hsm.LMK)
            is_aes = (hdr.algorithm.upper() == "A")
        else:
            dek_raw = _get_key_raw(self.hsm, dek_str, default_variant=8)

        mode, data_len, rem = parse_mode_and_datalen(rem)

        if mode in ("11",):
            # FF1 FPE mode operates on string digits/hex
            raw_text = rem[:data_len]
            ff1 = FF1Cipher(dek_raw, radix=10)
            encrypted_str = ff1.encrypt(raw_text)
            return ErrorCodes.SUCCESS, encrypted_str.encode("ascii")

        if is_aes:
            has_iv = mode in ("01", "1", "06", "6")
            data_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=has_iv)
            iv_hex = rem[:32] if len(rem) >= 32 else "00" * 16
            iv_bytes = unhexlify(iv_hex)

            if mode in ("00", "0"):
                padded_data = pad_pkcs5(data_bytes, 16)
                cipher = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_ECB)
                encrypted = cipher.encrypt(padded_data)
            elif mode in ("01", "1"):
                padded_data = pad_pkcs5(data_bytes, 16)
                cipher = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CBC, iv=iv_bytes)
                encrypted = cipher.encrypt(padded_data)
            elif mode in ("06", "6"):
                encrypted = aes_ctr_crypt(dek_raw, data_bytes, iv_bytes)
            else:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported mode '{mode}'")
            return ErrorCodes.SUCCESS, hexlify(encrypted).upper()

        if len(dek_raw) == 16:
            dek_raw = dek_raw + dek_raw[:8]

        has_iv = mode in ("01", "1", "06", "6")
        data_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=has_iv)

        iv_hex = rem[:16] if len(rem) >= 16 else "0000000000000000"
        iv_bytes = unhexlify(iv_hex)

        if mode in ("00", "0"):
            padded_data = pad_pkcs5(data_bytes, 8)
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_ECB)
            encrypted = cipher.encrypt(padded_data)
        elif mode in ("01", "1"):
            padded_data = pad_pkcs5(data_bytes, 8)
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_CBC, iv=iv_bytes)
            encrypted = cipher.encrypt(padded_data)
        elif mode in ("06", "6"):
            encrypted = des3_ctr_crypt(dek_raw, data_bytes, iv_bytes)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported mode '{mode}'")

        return ErrorCodes.SUCCESS, hexlify(encrypted).upper()


@global_router.register("M2")
class M2Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M2 Decrypt Data Handler.
        Supports modes: '00'/'0' (ECB), '01'/'1' (CBC), '06'/'6' (CTR), '11' (FF1 FPE).
        """
        if _is_exact_wire_format(payload):
            mode, output_format, dek_raw, iv, message, radix, tweak, key_alg, ofb_flag, c_offset, c_len = _parse_exact_m0_m2(
                self.hsm, payload, decrypt=True
            )
            if key_alg == "A":
                if mode == "00":
                    decrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_ECB).decrypt(message)
                    response_iv = b""
                elif mode == "01":
                    decrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CBC, iv=iv).decrypt(message)
                    response_iv = message[-16:]
                elif mode == "02":
                    decrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CFB, iv=iv, segment_size=8).decrypt(message)
                    response_iv = (iv + message)[-16:]
                elif mode == "03":
                    decrypted = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CFB, iv=iv, segment_size=64).decrypt(message)
                    response_iv = (iv + message)[-16:]
                elif mode == "05":
                    decrypted, response_iv = _ofb_crypt(dek_raw, message, iv, key_alg)
                elif mode == "06":
                    decrypted = aes_ctr_crypt(dek_raw, message, iv, c_offset, c_len)
                    response_iv = calc_ctr_output_iv(iv, len(message), 16, c_offset, c_len)
                elif mode == "11":
                    ff1 = FF1Cipher(dek_raw, radix=radix, tweak=tweak)
                    decrypted = ff1.decrypt(message.decode("ascii")).encode("ascii")
                    response_iv = b""
                else:
                    raise PayShieldException(ErrorCodes.INVALID_MODE, f"Unsupported mode '{mode}'")
            else:
                if mode == "00":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_ECB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_ECB)
                    decrypted = cipher.decrypt(message)
                    response_iv = b""
                elif mode == "01":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CBC if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CBC, iv=iv)
                    decrypted = cipher.decrypt(message)
                    response_iv = message[-8:]
                elif mode == "02":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CFB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=8)
                    decrypted = cipher.decrypt(message)
                    response_iv = (iv + message)[-8:]
                elif mode == "03":
                    cipher = _get_des_cipher(dek_raw, Crypto.Cipher.DES.MODE_CFB if len(dek_raw) == 8 else Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=64)
                    decrypted = cipher.decrypt(message)
                    response_iv = (iv + message)[-8:]
                elif mode == "05":
                    decrypted, response_iv = _ofb_crypt(dek_raw, message, iv, key_alg)
                elif mode == "06":
                    decrypted = des3_ctr_crypt(dek_raw, message, iv, c_offset, c_len)
                    response_iv = calc_ctr_output_iv(iv, len(message), 8, c_offset, c_len)
                elif mode == "11":
                    raise PayShieldException(ErrorCodes.MODE_REQUIRES_AES_KB_LMK, "FF1 requires AES Key Block LMK")
                else:
                    raise PayShieldException(ErrorCodes.INVALID_MODE, f"Unsupported mode '{mode}'")
            return ErrorCodes.SUCCESS, _format_exact_data_response(output_format, decrypted, response_iv)

        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 38:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "M2 payload too short")

        dek_str, rem = _extract_key_string(payload_str)
        is_aes = False
        if dek_str.startswith("S"):
            hdr, dek_raw = TR31KeyBlock.unwrap(dek_str, self.hsm.LMK)
            is_aes = (hdr.algorithm.upper() == "A")
        else:
            dek_raw = _get_key_raw(self.hsm, dek_str, default_variant=8)

        mode, data_len, rem = parse_mode_and_datalen(rem)

        if mode in ("11",):
            raw_text = rem[:data_len]
            ff1 = FF1Cipher(dek_raw, radix=10)
            decrypted_str = ff1.decrypt(raw_text)
            return ErrorCodes.SUCCESS, decrypted_str.encode("ascii")

        if is_aes:
            has_iv = mode in ("01", "1", "06", "6")
            try:
                encrypted_bytes = unhexlify(rem[: data_len * 2])
                rem = rem[data_len * 2 :]
            except Exception:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid hex data in M2 payload")
            iv_hex = rem[:32] if len(rem) >= 32 else "00" * 16
            iv_bytes = unhexlify(iv_hex)

            if mode in ("00", "0"):
                cipher = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_ECB)
                decrypted_padded = cipher.decrypt(encrypted_bytes)
                decrypted = unpad_pkcs5(decrypted_padded)
            elif mode in ("01", "1"):
                cipher = Crypto.Cipher.AES.new(dek_raw, Crypto.Cipher.AES.MODE_CBC, iv=iv_bytes)
                decrypted_padded = cipher.decrypt(encrypted_bytes)
                decrypted = unpad_pkcs5(decrypted_padded)
            elif mode in ("06", "6"):
                decrypted = aes_ctr_crypt(dek_raw, encrypted_bytes, iv_bytes)
            else:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported mode '{mode}'")
            return ErrorCodes.SUCCESS, hexlify(decrypted).upper()

        if len(dek_raw) == 16:
            dek_raw = dek_raw + dek_raw[:8]

        has_iv = mode in ("01", "1", "06", "6")
        try:
            encrypted_bytes = unhexlify(rem[: data_len * 2])
            rem = rem[data_len * 2 :]
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid hex data in M2 payload")

        iv_hex = rem[:16] if len(rem) >= 16 else "0000000000000000"
        iv_bytes = unhexlify(iv_hex)

        if mode in ("00", "0"):
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_ECB)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted = unpad_pkcs5(decrypted_padded)
        elif mode in ("01", "1"):
            cipher = Crypto.Cipher.DES3.new(dek_raw, Crypto.Cipher.DES3.MODE_CBC, iv=iv_bytes)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted = unpad_pkcs5(decrypted_padded)
        elif mode in ("06", "6"):
            decrypted = des3_ctr_crypt(dek_raw, encrypted_bytes, iv_bytes)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported mode '{mode}'")

        return ErrorCodes.SUCCESS, hexlify(decrypted).upper()


@global_router.register("M4")
class M4Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M4 Translate Data Block Handler.
        Payload: [SrcDEK] + [TgtDEK] + [SrcMode] + [TgtMode] + [DataLen: 4 hex] + [EncDataHex] (+ [SrcIV] + [TgtIV])
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 70:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "M4 payload too short")

        src_dek_str, rem = _extract_key_string(payload_str)
        tgt_dek_str, rem = _extract_key_string(rem)

        src_dek = _get_key_raw(self.hsm, src_dek_str, default_variant=8)
        tgt_dek = _get_key_raw(self.hsm, tgt_dek_str, default_variant=8)
        if len(src_dek) == 16:
            src_dek = src_dek + src_dek[:8]
        if len(tgt_dek) == 16:
            tgt_dek = tgt_dek + tgt_dek[:8]

        src_mode, tgt_mode, rem = parse_m4_modes(rem)

        data_len = int(rem[:4], 16)
        rem = rem[4:]

        enc_bytes = unhexlify(rem[: data_len * 2])
        rem = rem[data_len * 2 :]

        src_requires_iv = src_mode in ("01", "1", "06", "6")
        tgt_requires_iv = tgt_mode in ("01", "1", "06", "6")

        if src_requires_iv and tgt_requires_iv:
            src_iv_hex = rem[:16] if len(rem) >= 16 else "0000000000000000"
            rem = rem[16:] if len(rem) >= 16 else ""
            tgt_iv_hex = rem[:16] if len(rem) >= 16 else "0000000000000000"
            rem = rem[16:] if len(rem) >= 16 else ""
        elif src_requires_iv and not tgt_requires_iv:
            src_iv_hex = rem[:16] if len(rem) >= 16 else "0000000000000000"
            tgt_iv_hex = "0000000000000000"
        elif not src_requires_iv and tgt_requires_iv:
            src_iv_hex = "0000000000000000"
            if len(rem) >= 32:
                tgt_iv_hex = rem[16:32]
            elif len(rem) >= 16:
                tgt_iv_hex = rem[:16]
            else:
                tgt_iv_hex = "0000000000000000"
        else:
            src_iv_hex = "0000000000000000"
            tgt_iv_hex = "0000000000000000"

        src_iv = unhexlify(src_iv_hex)
        tgt_iv = unhexlify(tgt_iv_hex)

        # Decrypt source data
        if src_mode in ("00", "0"):
            cipher_src = Crypto.Cipher.DES3.new(src_dek, Crypto.Cipher.DES3.MODE_ECB)
            clear_padded = cipher_src.decrypt(enc_bytes)
            clear_bytes = unpad_pkcs5(clear_padded)
        elif src_mode in ("01", "1"):
            cipher_src = Crypto.Cipher.DES3.new(src_dek, Crypto.Cipher.DES3.MODE_CBC, iv=src_iv)
            clear_padded = cipher_src.decrypt(enc_bytes)
            clear_bytes = unpad_pkcs5(clear_padded)
        elif src_mode in ("06", "6"):
            clear_bytes = des3_ctr_crypt(src_dek, enc_bytes, src_iv)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported src mode '{src_mode}'")

        # Encrypt target data
        if tgt_mode in ("00", "0"):
            padded = pad_pkcs5(clear_bytes, 8)
            cipher_tgt = Crypto.Cipher.DES3.new(tgt_dek, Crypto.Cipher.DES3.MODE_ECB)
            new_enc = cipher_tgt.encrypt(padded)
        elif tgt_mode in ("01", "1"):
            padded = pad_pkcs5(clear_bytes, 8)
            cipher_tgt = Crypto.Cipher.DES3.new(tgt_dek, Crypto.Cipher.DES3.MODE_CBC, iv=tgt_iv)
            new_enc = cipher_tgt.encrypt(padded)
        elif tgt_mode in ("06", "6"):
            new_enc = des3_ctr_crypt(tgt_dek, clear_bytes, tgt_iv)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported tgt mode '{tgt_mode}'")

        return ErrorCodes.SUCCESS, hexlify(new_enc).upper()


@global_router.register("M6")
class M6Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M6 Generate MAC Handler.
        Payload: [TAK/ZAK] + [MAC Mode: '00'/'0'/'1'=ISO Alg1, '01'/'3'=ISO Alg3, '02'/'6'/'CMAC'=CMAC] + [DataLen: 4 hex] + [Data]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 38:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "M6 payload too short")

        mac_key_str, rem = _extract_key_string(payload_str)
        mac_key = _get_key_raw(self.hsm, mac_key_str, default_variant=6)

        mode, data_len, rem = parse_mode_and_datalen(rem)

        data_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=False)

        if mode in ("00", "0", "1"):
            mac = iso9797_alg1_mac(mac_key, data_bytes)
        elif mode in ("01", "3"):
            mac = iso9797_alg3_mac(mac_key, data_bytes)
        elif mode in ("02", "6", "CMAC"):
            mac = cmac_calc(mac_key, data_bytes)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported MAC algorithm mode '{mode}'")

        return ErrorCodes.SUCCESS, hexlify(mac).upper()


@global_router.register("M8")
class M8Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M8 Verify MAC Handler.
        Payload: [TAK/ZAK] + [MAC Mode] + [DataLen: 4 hex] + [MAC to verify: 16 hex] + [Data]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 54:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "M8 payload too short")

        mac_key_str, rem = _extract_key_string(payload_str)
        mac_key = _get_key_raw(self.hsm, mac_key_str, default_variant=6)

        mode, data_len, rem = parse_mode_and_datalen(rem)

        mac_to_verify = rem[:16].upper()
        rem = rem[16:]

        data_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=False)

        if mode in ("00", "0", "1"):
            computed_mac = iso9797_alg1_mac(mac_key, data_bytes)
        elif mode in ("01", "3"):
            computed_mac = iso9797_alg3_mac(mac_key, data_bytes)
        elif mode in ("02", "6", "CMAC"):
            computed_mac = cmac_calc(mac_key, data_bytes)
        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Unsupported MAC algorithm mode '{mode}'")

        computed_hex = hexlify(computed_mac).upper().decode("ascii")

        if computed_hex != mac_to_verify:
            raise PayShieldException(ErrorCodes.KCV_MISMATCH, f"MAC verification failed: computed '{computed_hex}' != '{mac_to_verify}'")

        return ErrorCodes.SUCCESS, b""


HASH_ALGO_BY_USAGE = {
    "61": hashlib.sha1,
    "62": hashlib.sha224,
    "63": hashlib.sha256,
    "64": hashlib.sha384,
    "65": hashlib.sha512,
}

HASH_ALGO_BY_ID = {
    "01": hashlib.sha1,
    "05": hashlib.sha224,
    "06": hashlib.sha256,
    "07": hashlib.sha384,
    "08": hashlib.sha512,
}


HASH_ID_BY_USAGE = {
    "61": "01",
    "62": "05",
    "63": "06",
    "64": "07",
    "65": "08",
}

USAGE_BY_HASH_ID = {
    "01": "61",
    "05": "62",
    "06": "63",
    "07": "64",
    "08": "65",
}


def _extract_zmk_for_hmac(hsm, payload: bytes) -> Tuple[bytes, bytes]:
    """
    Extracts and decrypts ZMK from the start of payload.
    Returns (clear_zmk_bytes, rem_payload_bytes).
    """
    if not payload:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Empty payload for ZMK extraction")

    if payload.startswith((b"S", b"R")):
        if payload.startswith(b"S") and len(payload) >= 5 and payload[1:5].isdigit():
            kb_len = int(payload[1:5].decode("ascii"))
        elif len(payload) >= 6 and payload[2:6].isdigit():
            kb_len = 1 + int(payload[2:6].decode("ascii"))
        else:
            kb_len = 16
        zmk_block = payload[:kb_len].decode("ascii")
        rem = payload[kb_len:]
        _, clear_zmk = TR31KeyBlock.unwrap(zmk_block, hsm.LMK)
        return clear_zmk, rem

    scheme = chr(payload[0]).upper()
    if scheme in ("U", "X", "M"):
        target_len = 33
    elif scheme in ("T", "Y"):
        target_len = 49
    elif scheme in ("D", "A"):
        target_len = 33 if len(payload) >= 33 else 17
    elif scheme == "E":
        target_len = 49 if len(payload) >= 49 else (33 if len(payload) >= 33 else 17)
    elif scheme == "Z":
        target_len = 17
    else:
        target_len = 48 if len(payload) >= 48 and all(chr(c) in string.hexdigits for c in payload[:48]) else 32

    zmk_str = payload[:target_len].decode("ascii")
    rem = payload[target_len:]
    _, enc_zmk = _parse_key_payload(zmk_str)
    clear_zmk = hsm.lmk_engine.decrypt_under_lmk(enc_zmk, variant=KEY_TYPE_VARIANTS["000"])
    return clear_zmk, rem


def _encrypt_hmac_under_lmk(lmk_engine, raw_key: bytes) -> bytes:
    pad_len = (8 - (len(raw_key) % 8)) % 8
    padded = raw_key + (b"\x00" * pad_len)
    return lmk_engine.encrypt_under_lmk(padded, variant=1)


def _decrypt_hmac_under_lmk(lmk_engine, enc_key: bytes, key_len: int) -> bytes:
    pad_len = (8 - (len(enc_key) % 8)) % 8
    if pad_len != 0:
        enc_key = enc_key + (b"\x00" * pad_len)
    decrypted = lmk_engine.decrypt_under_lmk(enc_key, variant=1)
    return decrypted[:key_len]


@global_router.register("L0")
class L0Handler(BaseCommandHandler):
    """
    L0 Generate an HMAC Secret Key.
    Returns L1 + '00' + Key Length ('FFFF' for Key Block) + HMAC Key Block (without scheme prefix).
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        if len(payload) < 10:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "L0 payload too short")

        try:
            hash_id = payload[:2].decode("ascii")
            hmac_usage = payload[2:4].decode("ascii")
            key_len_bytes = int(payload[4:8].decode("ascii"))
            key_format = payload[8:10].decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Invalid L0 header fields: {exc}")

        if key_format not in ("00", "04"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_FORMAT, f"Invalid HMAC key format: {key_format}")

        rem = payload[10:]
        if b"%" in rem:
            rem = rem.split(b"%", 1)[0]

        key_usage = USAGE_BY_HASH_ID.get(hash_id, "63")
        algorithm = "H0"
        mode_of_use = "C"
        key_version = "00"
        exportability = "E"

        if b"#" in rem:
            spec = rem.split(b"#", 1)[1].decode("ascii", errors="ignore")
            if len(spec) >= 2:
                key_usage = spec[:2]
            if len(spec) >= 4:
                algorithm = spec[2:4]
            if len(spec) >= 5:
                mode_of_use = spec[4]
            if len(spec) >= 7:
                key_version = spec[5:7]
            if len(spec) >= 8:
                exportability = spec[7]

        if key_format == "00":
            if hash_id not in HASH_ALGO_BY_ID:
                raise PayShieldException(ErrorCodes.INVALID_HASH_IDENTIFIER, f"Invalid hash ID: {hash_id}")
            if hmac_usage not in ("01", "02", "03"):
                raise PayShieldException(ErrorCodes.INVALID_HMAC_KEY_USAGE, f"Invalid HMAC key usage: {hmac_usage}")
            digest_len = HASH_ALGO_BY_ID[hash_id]().digest_size
            if key_len_bytes < digest_len // 2:
                raise PayShieldException(ErrorCodes.HMAC_LENGTH_ERROR, f"HMAC key length {key_len_bytes} is less than L/2 ({digest_len // 2})")
        else:
            digest_len = HASH_ALGO_BY_USAGE.get(key_usage, hashlib.sha256)().digest_size
            if key_len_bytes < digest_len // 2:
                raise PayShieldException(ErrorCodes.HMAC_LENGTH_ERROR, f"HMAC key length {key_len_bytes} is less than L/2 ({digest_len // 2})")

        raw_key = os.urandom(key_len_bytes)

        if key_format == "04" or b"#" in payload:
            hdr = TR31Header(
                version_id="1",
                key_length=128,
                key_usage=key_usage,
                algorithm="H",
                mode_of_use=mode_of_use,
                key_version=key_version,
                exportability=exportability,
                optional_headers=b"",
                lmk_identifier="00",
            )
            key_block = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
            resp_payload = b"FFFF" + key_block
        else:
            enc_key = _encrypt_hmac_under_lmk(self.hsm.lmk_engine, raw_key)
            resp_payload = f"{len(enc_key):04d}".encode("ascii") + enc_key

        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("LQ")
class LQHandler(BaseCommandHandler):
    """
    LQ Generate an HMAC on a Block of Data.
    Returns LR + '00' + HMAC Length (4 N) + HMAC (n B raw bytes).
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        if len(payload) < 17:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LQ payload too short")

        try:
            hash_id = payload[:2].decode("ascii")
            hmac_len = int(payload[2:6].decode("ascii"))
            key_format = payload[6:8].decode("ascii")
            key_len_field = payload[8:12].decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Invalid LQ header fields: {exc}")

        if key_format not in ("00", "04"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_FORMAT, f"Invalid key format: '{key_format}'")

        rem = payload[12:]

        if key_format == "04":
            if rem.startswith((b"S", b"R")):
                kb_len = 1 + int(rem[2:6].decode("ascii"))
            else:
                kb_len = int(rem[1:5].decode("ascii"))
            key_bytes_block = rem[:kb_len]
            rem_after_key = rem[kb_len:]

            if rem_after_key.startswith(b";"):
                rem_after_key = rem_after_key[1:]

            if len(rem_after_key) < 5:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing data length in LQ payload")

            try:
                data_len = int(rem_after_key[:5].decode("ascii"))
            except ValueError:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid data length in LQ payload")

            message_data = rem_after_key[5:5 + data_len]
            rem_after_data = rem_after_key[5 + data_len:]

            hdr, clear_key = TR31KeyBlock.unwrap(key_bytes_block.decode("ascii"), self.hsm.LMK)
            if hdr.key_usage not in HASH_ALGO_BY_USAGE:
                raise PayShieldException(ErrorCodes.INVALID_KEY_USAGE, f"Invalid HMAC Key Block usage: {hdr.key_usage}")
            if hdr.mode_of_use not in ("C", "G", "N"):
                raise PayShieldException(ErrorCodes.INVALID_MODE_OF_USE, f"Invalid HMAC Key Block mode of use: {hdr.mode_of_use}")
            hash_func = HASH_ALGO_BY_USAGE[hdr.key_usage]
        else:
            if hash_id not in HASH_ALGO_BY_ID:
                raise PayShieldException(ErrorCodes.INVALID_HASH_IDENTIFIER, f"Invalid hash identifier: '{hash_id}'")
            try:
                enc_key_len = int(key_len_field)
            except ValueError:
                enc_key_len = 32
            enc_key = rem[:enc_key_len]
            rem_after_key = rem[enc_key_len:]
            if not rem_after_key.startswith(b";"):
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing ';' delimiter in LQ payload for Variant LMK")
            rem_after_key = rem_after_key[1:]
            if len(rem_after_key) < 5:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing data length in LQ payload")
            data_len = int(rem_after_key[:5].decode("ascii"))
            message_data = rem_after_key[5:5 + data_len]
            rem_after_data = rem_after_key[5 + data_len:]
            hash_func = HASH_ALGO_BY_ID[hash_id]
            clear_key = _decrypt_hmac_under_lmk(self.hsm.lmk_engine, enc_key, hash_func().digest_size)

        digest_size = hash_func().digest_size
        if not (digest_size // 2 <= hmac_len <= digest_size):
            raise PayShieldException(ErrorCodes.HMAC_LENGTH_ERROR, f"HMAC length {hmac_len} out of range [{digest_size//2}, {digest_size}]")

        mac = hmac.new(clear_key, message_data, hash_func).digest()
        if hmac_len < len(mac):
            mac = mac[:hmac_len]

        hmac_len_str = f"{hmac_len:04d}".encode("ascii")
        resp_payload = hmac_len_str + mac
        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("LS")
class LSHandler(BaseCommandHandler):
    """
    LS Verify an HMAC on a Block of Data.
    Payload: HashId (2) + HMACLen (4) + HMAC (t bytes) + KeyFormat (2) + KeyLen (4) + Key + [;] + DataLen (5) + Data
    Returns LT + '00' on success, LT + '01' on failure.
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        if len(payload) < 20:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LS payload too short")

        try:
            hash_id = payload[:2].decode("ascii")
            hmac_len = int(payload[2:6].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Invalid LS header: {exc}")

        if len(payload) < 6 + hmac_len + 6:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LS payload too short for specified HMAC length")

        supplied_hmac = payload[6:6 + hmac_len]
        rem = payload[6 + hmac_len:]

        try:
            key_format = rem[:2].decode("ascii")
            key_len_field = rem[2:6].decode("ascii")
        except UnicodeDecodeError:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid key format or length in LS")

        if key_format not in ("00", "04"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_FORMAT, f"Invalid key format: '{key_format}'")

        rem_key = rem[6:]

        if key_format == "04":
            if rem_key.startswith((b"S", b"R")):
                kb_len = 1 + int(rem_key[2:6].decode("ascii"))
            else:
                kb_len = int(rem_key[1:5].decode("ascii"))
            key_bytes_block = rem_key[:kb_len]
            rem_after_key = rem_key[kb_len:]

            if rem_after_key.startswith(b";"):
                rem_after_key = rem_after_key[1:]

            if len(rem_after_key) < 5:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing data length in LS payload")

            try:
                data_len = int(rem_after_key[:5].decode("ascii"))
            except ValueError:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid data length in LS payload")

            message_data = rem_after_key[5:5 + data_len]
            rem_after_data = rem_after_key[5 + data_len:]

            hdr, clear_key = TR31KeyBlock.unwrap(key_bytes_block.decode("ascii"), self.hsm.LMK)
            if hdr.key_usage not in HASH_ALGO_BY_USAGE:
                raise PayShieldException(ErrorCodes.INVALID_KEY_USAGE, f"Invalid HMAC Key Block usage: {hdr.key_usage}")
            if hdr.mode_of_use not in ("C", "V", "N"):
                raise PayShieldException(ErrorCodes.INVALID_MODE_OF_USE, f"Invalid HMAC Key Block mode of use: {hdr.mode_of_use}")
            hash_func = HASH_ALGO_BY_USAGE[hdr.key_usage]
        else:
            if hash_id not in HASH_ALGO_BY_ID:
                raise PayShieldException(ErrorCodes.INVALID_HASH_IDENTIFIER, f"Invalid hash identifier: '{hash_id}'")
            try:
                enc_key_len = int(key_len_field)
            except ValueError:
                enc_key_len = 32
            enc_key = rem_key[:enc_key_len]
            rem_after_key = rem_key[enc_key_len:]
            if not rem_after_key.startswith(b";"):
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing ';' delimiter in LS payload for Variant LMK")
            rem_after_key = rem_after_key[1:]
            if len(rem_after_key) < 5:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing data length in LS payload")
            data_len = int(rem_after_key[:5].decode("ascii"))
            message_data = rem_after_key[5:5 + data_len]
            rem_after_data = rem_after_key[5 + data_len:]
            hash_func = HASH_ALGO_BY_ID[hash_id]
            clear_key = _decrypt_hmac_under_lmk(self.hsm.lmk_engine, enc_key, hash_func().digest_size)

        digest_size = hash_func().digest_size
        if not (digest_size // 2 <= hmac_len <= digest_size):
            raise PayShieldException(ErrorCodes.HMAC_LENGTH_ERROR, f"HMAC length {hmac_len} out of range")

        expected_mac = hmac.new(clear_key, message_data, hash_func).digest()
        if hmac_len < len(expected_mac):
            expected_mac = expected_mac[:hmac_len]

        if hmac.compare_digest(expected_mac, supplied_hmac):
            return ErrorCodes.SUCCESS, b""
        else:
            return ErrorCodes.VERIFICATION_FAILURE, b""


@global_router.register("LU")
class LUHandler(BaseCommandHandler):
    """
    LU Import an HMAC Key under a ZMK.
    Returns LV + '00' + Key Length ('FFFF' or 4 N) + HMAC Key under LMK.
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        clear_zmk, rem = _extract_zmk_for_hmac(self.hsm, payload)
        if len(rem) < 4:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LU payload too short after ZMK")

        len_field = rem[:4]
        if len_field == b"FFFF":
            rem_kb = rem[4:]
            if rem_kb.startswith(b"R"):
                kb_len = 1 + int(rem_kb[2:6].decode("ascii"))
                kb_str = rem_kb[:kb_len].decode("ascii")
                rem_after = rem_kb[kb_len:]
                transport_format = rem_after[:2].decode("ascii")
                lmk_format = rem_after[2:4].decode("ascii")
                rem_fields = rem_after[4:]
                hdr, raw_key = TR31KeyBlock.unwrap(kb_str, clear_zmk)
                hash_id = HASH_ID_BY_USAGE.get(hdr.key_usage, "06")
                key_usage = "03"
            else:
                if rem_kb.startswith(b"S"):
                    kb_len = int(rem_kb[1:5].decode("ascii"))
                elif len(rem_kb) >= 6 and rem_kb[2:6].isdigit():
                    kb_len = 1 + int(rem_kb[2:6].decode("ascii"))
                else:
                    kb_len = int(rem_kb[1:5].decode("ascii"))
                kb_str = rem_kb[:kb_len].decode("ascii")
                rem_after = rem_kb[kb_len:]
                transport_format = rem_after[:2].decode("ascii")
                lmk_format = rem_after[2:4].decode("ascii")
                rem_fields = rem_after[4:]
                hdr, raw_key = TR31KeyBlock.unwrap(kb_str, clear_zmk)
                hash_id = HASH_ID_BY_USAGE.get(hdr.key_usage, "06")
                key_usage = "03"
        else:
            key_len = int(len_field.decode("ascii"))
            enc_key_zmk = rem[4:4 + key_len]
            rem_after = rem[4 + key_len:]
            if rem_after.startswith(b";"):
                rem_after = rem_after[1:]
            transport_format = rem_after[:2].decode("ascii")
            lmk_format = rem_after[2:4].decode("ascii")
            rem_fields = rem_after[4:]

            if transport_format in ("01", "02", "03"):
                hash_id = rem_fields[:2].decode("ascii")
                key_usage = rem_fields[2:4].decode("ascii")
                orig_key_len = int(rem_fields[4:8].decode("ascii"))
                rem_fields = rem_fields[8:]
            else:
                hash_id = "06"
                key_usage = "03"
                orig_key_len = key_len

            des_key = clear_zmk if len(clear_zmk) in (16, 24) else (clear_zmk[:8] * 2 if len(clear_zmk) == 8 else clear_zmk[:24])
            if transport_format == "02":
                cipher = Crypto.Cipher.DES3.new(des_key, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
            else:
                cipher = Crypto.Cipher.DES3.new(des_key, Crypto.Cipher.DES3.MODE_ECB)
            decrypted = cipher.decrypt(enc_key_zmk)
            raw_key = decrypted[:orig_key_len]

        trailer = b""
        if b"\x19" in rem_fields:
            trailer = rem_fields.split(b"\x19", 1)[1]

        if lmk_format == "04" or b"#" in rem_fields:
            target_usage = USAGE_BY_HASH_ID.get(hash_id, "63")
            target_mode = "C"
            if b"#" in rem_fields:
                spec = rem_fields.split(b"#", 1)[1].decode("ascii", errors="ignore")
                if len(spec) >= 2: target_usage = spec[:2]
                if len(spec) >= 5: target_mode = spec[4]
            hdr = TR31Header(
                version_id="1",
                key_length=128,
                key_usage=target_usage,
                algorithm="H",
                mode_of_use=target_mode,
                key_version="00",
                exportability="E",
                optional_headers=b"",
                lmk_identifier="00",
            )
            key_block = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
            resp_payload = b"FFFF" + key_block
        else:
            enc_key_lmk = _encrypt_hmac_under_lmk(self.hsm.lmk_engine, raw_key)
            resp_payload = f"{len(enc_key_lmk):04d}".encode("ascii") + enc_key_lmk

        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("LW")
class LWHandler(BaseCommandHandler):
    """
    LW Export an HMAC Key under a ZMK.
    Returns LX + '00' + exported key payload.
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        clear_zmk, rem = _extract_zmk_for_hmac(self.hsm, payload)
        if len(rem) < 8:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LW payload too short after ZMK")

        lmk_key_format = rem[:2].decode("ascii")
        transport_format = rem[2:4].decode("ascii")
        key_len_field = rem[4:8].decode("ascii")
        rem_key = rem[8:]

        if lmk_key_format == "04":
            if rem_key.startswith((b"S", b"R")):
                kb_len = 1 + int(rem_key[2:6].decode("ascii"))
            else:
                kb_len = int(rem_key[1:5].decode("ascii"))
            kb_str = rem_key[:kb_len].decode("ascii")
            rem_after = rem_key[kb_len:]
            hdr, raw_key = TR31KeyBlock.unwrap(kb_str, self.hsm.LMK)
            hash_id = HASH_ID_BY_USAGE.get(hdr.key_usage, "06")
            key_usage = "03" if hdr.mode_of_use in ("C", "N") else ("01" if hdr.mode_of_use == "G" else "02")
        else:
            key_len = int(key_len_field)
            enc_key = rem_key[:key_len]
            rem_after = rem_key[key_len:]
            raw_key = _decrypt_hmac_under_lmk(self.hsm.lmk_engine, enc_key, key_len)
            hash_id = "06"
            key_usage = "03"

        des_key = clear_zmk if len(clear_zmk) in (16, 24) else (clear_zmk[:8] * 2 if len(clear_zmk) == 8 else clear_zmk[:24])
        if transport_format in ("00", "01", "02", "03"):
            pad_len = (8 - (len(raw_key) % 8)) % 8
            padded = raw_key + (b"\x00" * pad_len)
            if transport_format == "02":
                cipher = Crypto.Cipher.DES3.new(des_key, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
            else:
                cipher = Crypto.Cipher.DES3.new(des_key, Crypto.Cipher.DES3.MODE_ECB)
            enc_zmk = cipher.encrypt(padded)
            if transport_format == "00":
                resp_payload = f"{len(enc_zmk):04d}".encode("ascii") + enc_zmk
            else:
                resp_payload = f"{len(enc_zmk):04d}".encode("ascii") + enc_zmk + hash_id.encode("ascii") + key_usage.encode("ascii") + f"{len(raw_key):04d}".encode("ascii")
        elif transport_format == "04":
            usage = USAGE_BY_HASH_ID.get(hash_id, "63")
            hdr_zmk = TR31Header(
                version_id="1",
                key_length=128,
                key_usage=usage,
                algorithm="H",
                mode_of_use="C",
                key_version="00",
                exportability="E",
                optional_headers=b"",
                lmk_identifier="00",
            )
            kb_zmk = TR31KeyBlock.wrap(raw_key, hdr_zmk, clear_zmk)
            resp_payload = b"FFFF" + kb_zmk
        elif transport_format == "05":
            v_id = "D" if len(clear_zmk) in (16, 24, 32) else "B"
            hdr_zmk = TR31Header(
                version_id=v_id,
                key_length=128,
                key_usage="M7",
                algorithm="H",
                mode_of_use="C",
                key_version="00",
                exportability="E",
                optional_headers=b"HM0021",
                lmk_identifier="00",
            )
            kb_zmk = TR31KeyBlock.wrap(raw_key, hdr_zmk, clear_zmk)
            resp_payload = f"{len(kb_zmk):04X}".encode("ascii") + b"R" + kb_zmk
        else:
            raise PayShieldException(ErrorCodes.INVALID_TRANSPORT_FORMAT, f"Invalid transport format: {transport_format}")

        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("LY")
class LYHandler(BaseCommandHandler):
    """
    LY Translate an HMAC Key from Old LMK to New LMK or migrate format.
    Returns LZ + '00' + translated key payload.
    """
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        if len(payload) < 8:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "LY payload too short")

        input_format = payload[:2].decode("ascii")
        output_format = payload[2:4].decode("ascii")
        key_len_field = payload[4:8].decode("ascii")
        rem = payload[8:]

        if input_format not in ("00", "04"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_FORMAT, f"Invalid input HMAC key format: {input_format}")
        if output_format not in ("00", "04"):
            raise PayShieldException(ErrorCodes.INVALID_TRANSPORT_FORMAT, f"Invalid output HMAC key format: {output_format}")

        if input_format == "04":
            if rem.startswith((b"S", b"R")):
                kb_len = 1 + int(rem[2:6].decode("ascii"))
            else:
                kb_len = int(rem[1:5].decode("ascii"))
            kb_str = rem[:kb_len].decode("ascii")
            rem_after = rem[kb_len:]
            hdr, raw_key = TR31KeyBlock.unwrap(kb_str, self.hsm.LMK)
            target_usage = hdr.key_usage
            target_mode = hdr.mode_of_use
        else:
            key_len = int(key_len_field)
            enc_key = rem[:key_len]
            rem_after = rem[key_len:]
            raw_key = _decrypt_hmac_under_lmk(self.hsm.lmk_engine, enc_key, key_len)
            target_usage = "63"
            target_mode = "C"

        if b"#" in rem_after:
            spec = rem_after.split(b"#", 1)[1].decode("ascii", errors="ignore")
            if len(spec) >= 2: target_usage = spec[:2]
            if len(spec) >= 5: target_mode = spec[4]

        if output_format == "04":
            hdr = TR31Header(
                version_id="1",
                key_length=128,
                key_usage=target_usage,
                algorithm="H",
                mode_of_use=target_mode,
                key_version="00",
                exportability="E",
                optional_headers=b"",
                lmk_identifier="00",
            )
            key_block = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
            resp_payload = b"FFFF" + key_block
        else:
            enc_key = _encrypt_hmac_under_lmk(self.hsm.lmk_engine, raw_key)
            resp_payload = f"{len(enc_key):04d}".encode("ascii") + enc_key

        return ErrorCodes.SUCCESS, resp_payload
