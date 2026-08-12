"""
Data Protection & MAC Command Handlers:
- M0/M1 (Encrypt Data)
- M2/M3 (Decrypt Data)
- M4/M5 (Translate Data Block)
- M6/M7 (Generate MAC)
- M8/M9 (Verify MAC)
"""

import math
from binascii import hexlify, unhexlify
from typing import Tuple, Optional
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import Crypto.Cipher.AES

from pythales.commands.base import BaseCommandHandler
from pythales.commands.key_mgmt import _extract_key_string, _parse_key_payload, KEY_TYPE_VARIANTS
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock


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

    raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Invalid mode or data length field")


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

    raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Invalid M4 source or target mode")


def _get_key_raw(hsm, key_str: str, default_variant: int = 8) -> bytes:
    """Helper to extract raw key bytes from key string under LMK or TR-31 Key Block."""
    if key_str.startswith("S"):
        _, raw_key = TR31KeyBlock.unwrap(key_str, hsm.LMK)
        return raw_key
    scheme, enc_bytes = _parse_key_payload(key_str)
    return hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant=default_variant)


def des3_ctr_crypt(key: bytes, data: bytes, iv_bytes: bytes) -> bytes:
    """CTR mode stream encryption/decryption using 3DES."""
    block_size = 8
    iv_int = int.from_bytes(iv_bytes, "big")
    if len(key) == 16:
        key = key + key[:8]
    cipher_ecb = Crypto.Cipher.DES3.new(key, Crypto.Cipher.DES3.MODE_ECB)
    output = bytearray()
    num_blocks = (len(data) + block_size - 1) // block_size
    for i in range(num_blocks):
        counter_val = (iv_int + i) % (2 ** (block_size * 8))
        counter_block = counter_val.to_bytes(block_size, "big")
        keystream = cipher_ecb.encrypt(counter_block)
        chunk = data[i * block_size : (i + 1) * block_size]
        output.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
    return bytes(output)


class FF1Cipher:
    """NIST SP 800-38G Format-Preserving Encryption (FF1)."""
    def __init__(self, key: bytes, radix: int = 10, tweak: bytes = b""):
        self.key = key
        self.radix = radix
        self.tweak = tweak

    def _prf(self, data: bytes) -> bytes:
        if len(self.key) in (16, 24):
            k = self.key if len(self.key) == 24 else self.key + self.key[:8]
            cipher = Crypto.Cipher.DES3.new(k, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
            pad_len = (8 - (len(data) % 8)) % 8
            if pad_len:
                data += b"\x00" * pad_len
            return cipher.encrypt(data)[-8:]
        else:
            cipher = Crypto.Cipher.AES.new(self.key[:16], Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
            pad_len = (16 - (len(data) % 16)) % 16
            if pad_len:
                data += b"\x00" * pad_len
            return cipher.encrypt(data)[-16:]

    def encrypt(self, X: str) -> str:
        n = len(X)
        u = n // 2
        v = n - u
        A = [int(c, self.radix) for c in X[:u]]
        B = [int(c, self.radix) for c in X[u:]]

        b = int(math.ceil((v * math.log2(self.radix)) / 8.0))
        d = 4 * math.ceil(b / 4.0) + 4

        for i in range(10):
            m = u if i % 2 == 0 else v
            val_B = 0
            for digit in B:
                val_B = val_B * self.radix + digit

            P = bytes([1, 2, 1]) + self.radix.to_bytes(3, "big") + bytes([10, v & 0xFF]) + n.to_bytes(4, "big") + len(self.tweak).to_bytes(4, "big")
            Q = self.tweak + b"\x00" * ((-len(self.tweak) - b - 1) % 16) + bytes([i]) + val_B.to_bytes(b, "big")

            R_bytes = self._prf(P + Q)
            S = R_bytes
            cnt = 1
            while len(S) < d:
                S += self._prf(bytes(a ^ b for a, b in zip(R_bytes, cnt.to_bytes(len(R_bytes), "big"))))
                cnt += 1
            S = S[:d]

            val_S = int.from_bytes(S, "big")
            y = val_S % (self.radix ** m)

            val_A = 0
            for digit in A:
                val_A = val_A * self.radix + digit

            c = (val_A + y) % (self.radix ** m)

            C = []
            for _ in range(m):
                C.append(c % self.radix)
                c //= self.radix
            C.reverse()

            A = B
            B = C

        res = A + B
        return "".join(f"{digit:X}" if self.radix > 10 else str(digit) for digit in res)

    def decrypt(self, X: str) -> str:
        n = len(X)
        u = n // 2
        v = n - u
        A = [int(c, self.radix) for c in X[:u]]
        B = [int(c, self.radix) for c in X[u:]]

        b = int(math.ceil((v * math.log2(self.radix)) / 8.0))
        d = 4 * math.ceil(b / 4.0) + 4

        for i in range(9, -1, -1):
            m = u if i % 2 == 0 else v
            val_A = 0
            for digit in A:
                val_A = val_A * self.radix + digit

            P = bytes([1, 2, 1]) + self.radix.to_bytes(3, "big") + bytes([10, v & 0xFF]) + n.to_bytes(4, "big") + len(self.tweak).to_bytes(4, "big")
            Q = self.tweak + b"\x00" * ((-len(self.tweak) - b - 1) % 16) + bytes([i]) + val_A.to_bytes(b, "big")

            R_bytes = self._prf(P + Q)
            S = R_bytes
            cnt = 1
            while len(S) < d:
                S += self._prf(bytes(a ^ b for a, b in zip(R_bytes, cnt.to_bytes(len(R_bytes), "big"))))
                cnt += 1
            S = S[:d]

            val_S = int.from_bytes(S, "big")
            y = val_S % (self.radix ** m)

            val_B = 0
            for digit in B:
                val_B = val_B * self.radix + digit

            c = (val_B - y) % (self.radix ** m)

            C = []
            for _ in range(m):
                C.append(c % self.radix)
                c //= self.radix
            C.reverse()

            B = A
            A = C

        res = A + B
        return "".join(f"{digit:X}" if self.radix > 10 else str(digit) for digit in res)


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
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 38:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M0 payload too short")

        dek_str, rem = _extract_key_string(payload_str)
        dek_raw = _get_key_raw(self.hsm, dek_str, default_variant=8)
        if len(dek_raw) == 16:
            dek_raw = dek_raw + dek_raw[:8]

        mode, data_len, rem = parse_mode_and_datalen(rem)

        if mode in ("11",):
            # FF1 FPE mode operates on string digits/hex
            raw_text = rem[:data_len]
            ff1 = FF1Cipher(dek_raw, radix=10)
            encrypted_str = ff1.encrypt(raw_text)
            return ErrorCodes.SUCCESS, encrypted_str.encode("ascii")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported mode '{mode}'")

        return ErrorCodes.SUCCESS, hexlify(encrypted).upper()


@global_router.register("M2")
class M2Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        M2 Decrypt Data Handler.
        Supports modes: '00'/'0' (ECB), '01'/'1' (CBC), '06'/'6' (CTR), '11' (FF1 FPE).
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 38:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M2 payload too short")

        dek_str, rem = _extract_key_string(payload_str)
        dek_raw = _get_key_raw(self.hsm, dek_str, default_variant=8)
        if len(dek_raw) == 16:
            dek_raw = dek_raw + dek_raw[:8]

        mode, data_len, rem = parse_mode_and_datalen(rem)

        if mode in ("11",):
            raw_text = rem[:data_len]
            ff1 = FF1Cipher(dek_raw, radix=10)
            decrypted_str = ff1.decrypt(raw_text)
            return ErrorCodes.SUCCESS, decrypted_str.encode("ascii")

        has_iv = mode in ("01", "1", "06", "6")
        try:
            encrypted_bytes = unhexlify(rem[: data_len * 2])
            rem = rem[data_len * 2 :]
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Invalid hex data in M2 payload")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported mode '{mode}'")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M4 payload too short")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported src mode '{src_mode}'")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported tgt mode '{tgt_mode}'")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M6 payload too short")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported MAC algorithm mode '{mode}'")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "M8 payload too short")

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
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported MAC algorithm mode '{mode}'")

        computed_hex = hexlify(computed_mac).upper().decode("ascii")

        if computed_hex != mac_to_verify:
            raise PayShieldException(ErrorCodes.KCV_MISMATCH, f"MAC verification failed: computed '{computed_hex}' != '{mac_to_verify}'")

        return ErrorCodes.SUCCESS, b""
