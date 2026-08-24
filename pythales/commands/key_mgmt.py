"""
Key Management Command Handlers: A0/A1, BU/BV, A2/A3, A4/A5, A6/A7, GI/GJ, KW/KX.
"""

import os
from binascii import hexlify, unhexlify
from typing import Tuple, Optional

import Crypto.Cipher.DES3
import Crypto.Cipher.AES
from pythales.commands.base import BaseCommandHandler

from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.lmk import LMKEngine
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header, parse_header

# Map PayShield Key Types to LMK Variants
KEY_TYPE_VARIANTS = {
    "000": 1,   # ZMK / KEK
    "001": 2,   # ZPK
    "002": 7,   # TPK (Variant 7)
    "003": 4,   # CVK (Variant 4)
    "005": 3,   # PVK
    "008": 6,   # ZAK (LMK pair 26-27 in payShield)
    "00A": 8,   # ZEK (LMK pair 30-31 in payShield)
    "00B": 8,   # DEK (LMK pair 32-33 in payShield)
    "30B": 3,   # TEK (LMK pair 32-33, variant 3 in payShield)
    "402": 4,   # CVK
}


def _extract_key_string(data_str: str) -> Tuple[str, str]:
    """
    Extract key string dynamically based strictly on scheme character:
    - 'U' / 'X': 33 characters (1 scheme + 32 hex) or 17 characters if single-length
    - 'T' / 'Y': 49 characters (1 scheme + 48 hex)
    - 'Z' / 'D' / 'E' / 'A': 17 characters (1 scheme + 16 hex)
    - 'S' / 'R': TR-31 / Thales Key Block (dynamic total length parsed from header indices 1:5 or 2:6 if Scheme-prefixed)
    Returns (extracted_key_str, remaining_str).
    """
    if not data_str:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Empty key data string")
    scheme = data_str[0].upper()
    if scheme in ("U", "X", "M"):
        target_len = 33
    elif scheme in ("T", "Y"):
        target_len = 49
    elif scheme in ("D", "A"):
        target_len = 33 if len(data_str) >= 33 else 17
    elif scheme == "E":
        target_len = 49 if len(data_str) >= 49 else (33 if len(data_str) >= 33 else 17)
    elif scheme == "Z":
        target_len = 17
    elif scheme in ("S", "R"):
        if len(data_str) < 16:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "TR-31 header too short")
        if (
            len(data_str) >= 17
            and data_str[1] in ("0", "1", "A", "B", "C", "D")
            and data_str[2:6].isdigit()
            and int(data_str[2:6]) >= 16
            and 1 + int(data_str[2:6]) <= len(data_str)
        ):
            target_len = 1 + int(data_str[2:6])
        elif data_str[1:5].isdigit() and data_str[1] == "0":
            target_len = int(data_str[1:5])
        elif len(data_str) >= 17 and data_str[2:6].isdigit() and data_str[2] == "0":
            target_len = 1 + int(data_str[2:6])
        elif data_str[1:5].isdigit():
            target_len = int(data_str[1:5])
        elif len(data_str) >= 17 and data_str[2:6].isdigit():
            target_len = 1 + int(data_str[2:6])
        else:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, f"Invalid TR-31 block length field: '{data_str[1:6]}'")
        if target_len < 16:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, f"TR-31 block length too small: {target_len}")



    else:
        raise PayShieldException(ErrorCodes.INVALID_KEY_SCHEME, f"Unsupported key scheme prefix: '{scheme}'")

    if len(data_str) < target_len:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Key string incomplete: expected {target_len} chars, got {len(data_str)}")

    return data_str[:target_len], data_str[target_len:]


def _parse_key_payload(key_str: str) -> Tuple[str, bytes]:
    """Helper to extract scheme character and raw encrypted key bytes from key string."""
    if not key_str:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Empty key string")
    scheme = key_str[0].upper()
    hex_data = key_str[1:]
    expected_hex_len = 48 if scheme in ("T", "Y") else 32
    if len(hex_data) >= expected_hex_len:
        hex_data = hex_data[:expected_hex_len]
    try:
        raw_bytes = unhexlify(hex_data)
    except Exception:
        raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Invalid hex in key string: '{hex_data}'")
    return scheme, raw_bytes


@global_router.register("A0")
class A0Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        A0 Generate Key Handler.
        Payload format:
        [Mode: 1 char ('0'=LMK, '1'=ZMK)] + [KeyType: 3 chars] + [KeyScheme: 1 char ('U','T','S','X','Y','M')]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 5:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "A0 payload too short")

        mode = payload_str[0]
        key_type = payload_str[1:4]
        key_scheme = payload_str[4].upper()

        if key_type not in KEY_TYPE_VARIANTS and key_type != "FFF":
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        if key_scheme not in ("U", "T", "S", "X", "Y", "M", "R"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_SCHEME, f"Unsupported key scheme: '{key_scheme}'")

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        rem_spec = payload_str[5:]
        if rem_spec.startswith(";"):
            rem_spec = rem_spec[1:]

        default_usage = "D0" if key_type in ("008", "00B") else "21" if key_type in ("001", "002") else "C0" if key_type == "000" else "52" if key_type == "402" else "00"
        algorithm = "T"
        mode_of_use = "B"
        key_version = "00"
        exportability = "E" if mode == "1" else "N"

        export_scheme = key_scheme
        zmk_str = ""
        rem_after_zmk = ""

        if mode == "1":
            rem = rem_spec
            if rem and rem[0] in ("0", "1"):  # optional ZMK flag
                rem = rem[1:]

            if not rem:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing ZMK for mode 1")

            zmk_str, rem_after_zmk = _extract_key_string(rem)
            # Strip optional 6-char hex KCV of ZMK if present before export scheme / spec
            if len(rem_after_zmk) >= 7 and all(c in "0123456789ABCDEFabcdef" for c in rem_after_zmk[:6]) and rem_after_zmk[6].upper() in ("S", "R", "U", "T", "X", "Y", "M", "E", "#"):
                rem_after_zmk = rem_after_zmk[6:]
            elif len(rem_after_zmk) == 6 and all(c in "0123456789ABCDEFabcdef" for c in rem_after_zmk):
                rem_after_zmk = ""

            if rem_after_zmk:
                export_scheme = rem_after_zmk[0].upper()
                if "#" in rem_after_zmk:
                    spec_source = rem_after_zmk.split("#", 1)[1]
                elif len(rem_after_zmk) >= 4 and rem_after_zmk[1:3].isalnum():
                    spec_source = rem_after_zmk[1:]
                else:
                    spec_source = ""
            else:
                spec_source = ""

        else:
            if "#" in rem_spec:
                spec_source = rem_spec.split("#", 1)[1]
            elif len(rem_spec) >= 3 and rem_spec[0:2].isalnum() and rem_spec[2].upper() in ("A", "T", "D", "R", "1", "2", "3"):
                spec_source = rem_spec
            else:
                spec_source = ""

        if spec_source and len(spec_source) >= 2 and spec_source[0:2].isalnum():
            default_usage = spec_source[0:2].upper()
            idx = 2
            if len(spec_source) >= 4 and spec_source[2:4].upper() in ("A1", "A2", "A3", "T2", "T3"):
                algorithm = spec_source[2:4].upper()
                idx = 4
            elif len(spec_source) >= 3 and spec_source[2].upper() in ("A", "T", "D", "R"):
                algorithm = spec_source[2].upper()
                idx = 3

            if len(spec_source) >= idx + 1:
                mode_of_use = spec_source[idx].upper()
            if len(spec_source) >= idx + 3:
                key_version = spec_source[idx+1:idx+3].upper()
            if len(spec_source) >= idx + 4:
                exportability = spec_source[idx+3].upper()

        # Determine raw key length and TR31Header algorithm ('A' or 'T')
        if algorithm == "A3":
            key_len = 32
            hdr_algorithm = "A"
        elif algorithm == "A2":
            key_len = 24
            hdr_algorithm = "A"
        elif algorithm in ("A1", "A"):
            key_len = 16
            hdr_algorithm = "A"
        elif key_scheme in ("T", "Y") or algorithm == "T3":
            key_len = 24
            hdr_algorithm = "T"
        elif algorithm == "T2":
            key_len = 16
            hdr_algorithm = "T"
        else:
            key_len = 16
            hdr_algorithm = "T"

        raw_key = os.urandom(key_len)

        zmk_raw = None
        lmk_identifier = "00"
        if mode == "1":
            if zmk_str.startswith(("S", "R")):
                zmk_header, zmk_raw = TR31KeyBlock.unwrap(zmk_str, self.hsm.LMK)
                lmk_identifier = zmk_header.lmk_identifier
            else:
                _, zmk_enc_bytes = _parse_key_payload(zmk_str)
                zmk_raw = self.hsm.lmk_engine.decrypt_under_lmk(
                    zmk_enc_bytes, variant=KEY_TYPE_VARIANTS["000"]
                )

        if key_scheme in ("S", "R"):
            if key_scheme == "S":
                v_id = "1" if hdr_algorithm == "A" else "0"
            else:
                v_id = "D" if hdr_algorithm == "A" else "R"
            hdr = TR31Header(
                version_id=v_id,
                key_length=80,
                key_usage=default_usage,
                algorithm=hdr_algorithm,
                mode_of_use=mode_of_use,
                key_version=key_version,
                exportability=exportability,
                lmk_identifier=lmk_identifier,
            )
            # Wrap under LMK
            key_block = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
            if v_id in ("0", "1", "D"):
                key_lmk_hex = key_scheme.encode("ascii") + key_block
            else:
                key_lmk_hex = key_block
        else:
            enc_key_bytes = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
            key_lmk_hex = key_scheme.encode("ascii") + hexlify(enc_key_bytes).upper()

        kcv = LMKEngine.generate_kcv(raw_key, algorithm=algorithm).encode("ascii")

        if mode == "0":
            return ErrorCodes.SUCCESS, key_lmk_hex + kcv
        elif mode == "1":
            if export_scheme in ("S", "R"):
                hdr_zmk_alg = "A" if algorithm.startswith("A") else "T"
                if export_scheme == "S":
                    v_id_zmk = "1" if hdr_zmk_alg == "A" else "0"
                else:
                    v_id_zmk = "D" if hdr_zmk_alg == "A" else "R"
                hdr_zmk = TR31Header(
                    version_id=v_id_zmk,
                    key_length=80,
                    key_usage=default_usage,
                    algorithm=hdr_zmk_alg,
                    mode_of_use=mode_of_use,
                    key_version=key_version,
                    exportability=exportability,
                    lmk_identifier=lmk_identifier,
                )
                key_block_zmk = TR31KeyBlock.wrap(raw_key, hdr_zmk, zmk_raw)
                if v_id_zmk in ("0", "1", "D"):
                    key_zmk_hex = export_scheme.encode("ascii") + key_block_zmk
                else:
                    key_zmk_hex = key_block_zmk
            else:
                if algorithm.startswith("A"):
                    zmk_key = zmk_raw[:32] if len(zmk_raw) >= 32 else (zmk_raw[:24] if len(zmk_raw) >= 24 else zmk_raw[:16])
                    aes_cipher = Crypto.Cipher.AES.new(zmk_key, Crypto.Cipher.AES.MODE_ECB)
                    enc_key_zmk = aes_cipher.encrypt(raw_key)
                else:
                    zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw[:16] if len(zmk_raw) == 16 else zmk_raw[:24], Crypto.Cipher.DES3.MODE_ECB)
                    enc_key_zmk = zmk_cipher.encrypt(raw_key)
                key_zmk_hex = export_scheme.encode("ascii") + hexlify(enc_key_zmk).upper()

            return ErrorCodes.SUCCESS, key_lmk_hex + key_zmk_hex + kcv

        else:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, f"Invalid mode '{mode}'")






@global_router.register("BU")
class BUHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        BU Generate KCV Handler.
        Payload: [KeyType: 2 or 3 chars] + [optional KeyLengthFlag: 1 char] + [KeyUnderLMK: 1 char scheme + hex]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 4:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "BU payload too short")

        if payload_str[:3] in KEY_TYPE_VARIANTS:
            key_type = payload_str[:3]
            key_str = payload_str[3:]
        elif "0" + payload_str[:2] in KEY_TYPE_VARIANTS:
            key_type = "0" + payload_str[:2]
            key_str = payload_str[2:]
        else:
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{payload_str[:3]}'")

        # If length flag '1' or '2' precedes scheme 'U'/'T'/'X'/'Y'
        if len(key_str) > 1 and key_str[0] in ("1", "2", "3") and key_str[1] in ("U", "T", "S", "X", "Y"):
            key_str = key_str[1:]

        if key_str.startswith("S"):
            _, raw_key = TR31KeyBlock.unwrap(key_str, self.hsm.LMK)
        else:
            scheme, enc_key = _parse_key_payload(key_str)
            variant = KEY_TYPE_VARIANTS.get(key_type, 0)
            raw_key = self.hsm.lmk_engine.decrypt_under_lmk(enc_key, variant)
        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")
        return ErrorCodes.SUCCESS, kcv


@global_router.register("A2")
class A2Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        A2 Generate & Print Component Handler.
        Payload format: [CompMode: 1 char ('0'=2 comps, '1'=3 comps)] + [KeyType: 3 chars] + [KeyScheme: 1 char]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 5:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "A2 payload too short")

        comp_mode = payload_str[0]
        key_type = payload_str[1:4]
        key_scheme = payload_str[4].upper()

        if key_type not in KEY_TYPE_VARIANTS:
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        num_comps = 3 if comp_mode == "1" else 2
        key_len = 24 if key_scheme in ("T", "Y") else 16

        comps = [os.urandom(key_len) for _ in range(num_comps)]
        raw_key = comps[0]
        for c in comps[1:]:
            raw_key = bytes(a ^ b for a, b in zip(raw_key, c))

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
        key_lmk_hex = key_scheme.encode("ascii") + hexlify(enc_key_lmk).upper()

        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")

        comp_hexs = [key_scheme.encode("ascii") + hexlify(c).upper() for c in comps]
        resp_payload = key_lmk_hex + kcv + b"".join(comp_hexs)
        return ErrorCodes.SUCCESS, resp_payload


@global_router.register("A4")
class A4Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        A4 Form Key from Components Handler.
        Payload format:
        [NumComps: 1 char ('2' or '3')] + [KeyType: 3 chars] + [KeyScheme: 1 char] + [Comp1] + [Comp2] + [optional Comp3]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 5:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "A4 payload too short")

        num_comps_str = payload_str[0]
        num_comps = 3 if num_comps_str == "3" else 2
        key_type = payload_str[1:4]
        key_scheme = payload_str[4].upper()

        if key_type not in KEY_TYPE_VARIANTS:
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        comp_hex_len = 48 if key_scheme in ("T", "Y") else 32
        rem = payload_str[5:]

        comps = []
        for _ in range(num_comps):
            if not rem:
                raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing component in A4 payload")
            if rem[0] in ("U", "T", "X", "Y"):
                rem = rem[1:]
            comp_hex = rem[:comp_hex_len]
            rem = rem[comp_hex_len:]
            comps.append(unhexlify(comp_hex))

        raw_key = comps[0]
        for c in comps[1:]:
            raw_key = bytes(a ^ b for a, b in zip(raw_key, c))

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
        key_lmk_hex = key_scheme.encode("ascii") + hexlify(enc_key_lmk).upper()

        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")
        return ErrorCodes.SUCCESS, key_lmk_hex + kcv


@global_router.register("A6")
class A6Handler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        A6 Import / Translate Key under ZMK to LMK Handler.
        Payload format:
        [KeyType: 3 chars] + [ZMK under LMK: Scheme + Hex] + [Key under ZMK: Scheme + Hex] + [TargetKeyScheme: 1 char]
        The command layout follows Core Host Commands Guide V1.9b Rev C,
        section "Import a Key" (A6/A7).  Variant/X9.17 DEK import remains
        valid with a Variant LMK; the Guide's restriction applies only when
        the HSM itself uses a Key Block LMK.
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 36:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "A6 payload too short")

        parts = payload_str.split(";") if ";" in payload_str else [payload_str]
        main_str = parts[0]

        key_type = main_str[:3]
        if key_type not in KEY_TYPE_VARIANTS and key_type != "FFF":
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        rem = main_str[3:]

        # ZMK under LMK (dynamic parsing)
        if rem and rem[0] in "0123456789ABCDEFabcdef":
            zmk_str, rem = rem[:16], rem[16:]
        else:
            zmk_str, rem = _extract_key_string(rem)
        if zmk_str[0].upper() not in ("S", "U", "T") and len(zmk_str) != 16:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Invalid ZMK scheme in A6")
        if zmk_str.startswith("S"):
            _, zmk_raw = TR31KeyBlock.unwrap(zmk_str, self.hsm.LMK)
        else:
            if len(zmk_str) == 16:
                zmk_enc_bytes = unhexlify(zmk_str)
            else:
                _, zmk_enc_bytes = _parse_key_payload(zmk_str)
            zmk_raw = self.hsm.lmk_engine.decrypt_under_lmk(zmk_enc_bytes, variant=KEY_TYPE_VARIANTS["000"])

        # Key under ZMK
        if not rem:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing key under ZMK")

        if rem[0] in "0123456789ABCDEFabcdef":
            key_zmk_str, trailing = rem[:16], rem[16:]
            key_zmk_scheme = "Z"
        else:
            key_zmk_str, trailing = _extract_key_string(rem)
            key_zmk_scheme = key_zmk_str[0].upper()
        target_scheme = trailing[0].upper() if trailing else ("Z" if len(key_zmk_str) == 16 else key_zmk_scheme)

        if target_scheme not in ("Z", "U", "T", "S"):
            raise PayShieldException(ErrorCodes.INVALID_KEY_SCHEME, f"Unsupported target key scheme: '{target_scheme}'")

        if key_zmk_scheme in ("R", "S"):
            hdr, raw_key = TR31KeyBlock.unwrap(key_zmk_str, zmk_raw)
        else:
            if key_zmk_scheme == "Z":
                key_zmk_enc_bytes = unhexlify(key_zmk_str)
            else:
                _, key_zmk_enc_bytes = _parse_key_payload(key_zmk_str)
            if key_zmk_scheme in ("M", "O"):
                iv_field = trailing[1:17]
                if len(iv_field) != 16:
                    raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "A6 CBC key scheme requires a 16H IV")
                zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw, Crypto.Cipher.DES3.MODE_CBC, iv=unhexlify(iv_field))
            else:
                zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw, Crypto.Cipher.DES3.MODE_ECB)
            raw_key = zmk_cipher.decrypt(key_zmk_enc_bytes)

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        if target_scheme == "S":
            default_usage = "D0" if key_type == "00B" else "22" if key_type == "00A" else "23" if key_type == "30B" else "00"
            hdr = TR31Header(
                version_id="S",
                key_length=80,
                key_usage=default_usage,
                algorithm="T",
                mode_of_use="B",
                key_version="00",
                exportability="E"
            )
            key_lmk_hex = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
        else:
            if target_scheme == "T" and len(raw_key) == 16:
                raw_key = raw_key + raw_key[:8]
            enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
            scheme_prefix = b"" if target_scheme == "Z" else target_scheme.encode("ascii")
            key_lmk_hex = scheme_prefix + hexlify(enc_key_lmk).upper()

        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")
        return ErrorCodes.SUCCESS, key_lmk_hex + kcv


@global_router.register("GI")
class GIHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        GI Import Key under RSA / Translate Key Scheme Handler.
        Payload format:
        [KeyType: 3 chars] + [SourceScheme: 1 char] + [TargetScheme: 1 char] + [KeyData]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 5:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "GI payload too short")

        key_type = payload_str[:3]
        if key_type not in KEY_TYPE_VARIANTS:
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        src_scheme = payload_str[3].upper()
        tgt_scheme = payload_str[4].upper()
        key_data = payload_str[5:]

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)

        if src_scheme == "S":
            # Unwrap TR-31 key block using LMK as KBMK
            hdr, raw_key = TR31KeyBlock.unwrap(key_data, self.hsm.LMK)
        else:
            src_sch, enc_bytes = _parse_key_payload(key_data if key_data.startswith(src_scheme) else src_scheme + key_data)
            raw_key = self.hsm.lmk_engine.decrypt_under_lmk(enc_bytes, variant)

        if tgt_scheme == "S":
            default_usage = "21" if key_type in ("001", "002") else "C0" if key_type == "000" else "52" if key_type == "402" else "00"
            hdr = TR31Header(
                version_id="S",
                key_length=80,
                key_usage=default_usage,
                algorithm="T",
                mode_of_use="B",
                key_version="00",
                exportability="E"
            )
            key_block = TR31KeyBlock.wrap(raw_key, hdr, self.hsm.LMK)
            translated_hex = key_block
        else:
            enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key, variant)
            translated_hex = tgt_scheme.encode("ascii") + hexlify(enc_key_lmk).upper()

        kcv = LMKEngine.generate_kcv(raw_key).encode("ascii")
        return ErrorCodes.SUCCESS, translated_hex + kcv


@global_router.register("KW")
class KWHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        KW Generate TR-31 Key Block Handler.
        Payload format:
        [KeyType: 3 chars] + [KBMK under LMK: Scheme + Hex] + [TR-31 Header: 16+ chars ASCII]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 36:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "KW payload too short")

        key_type = payload_str[:3]
        if key_type not in KEY_TYPE_VARIANTS:
            raise PayShieldException(ErrorCodes.INVALID_KEY_TYPE, f"Invalid key type: '{key_type}'")

        kbmk_str, header_str = _extract_key_string(payload_str[3:])

        if not header_str:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Missing TR-31 header in KW payload")

        if kbmk_str.startswith("S"):
            _, kbmk_raw = TR31KeyBlock.unwrap(kbmk_str, self.hsm.LMK)
        else:
            kbmk_scheme, kbmk_enc_bytes = _parse_key_payload(kbmk_str)
            kbmk_raw = self.hsm.lmk_engine.decrypt_under_lmk(kbmk_enc_bytes, variant=KEY_TYPE_VARIANTS["000"])

        hdr_obj = parse_header(header_str)
        key_len = 32 if hdr_obj.algorithm == "A" else 16
        raw_key = os.urandom(key_len)

        key_block = TR31KeyBlock.wrap(raw_key, hdr_obj, kbmk_raw)

        variant = KEY_TYPE_VARIANTS.get(key_type, 0)
        enc_key_lmk = self.hsm.lmk_engine.encrypt_under_lmk(raw_key[:16], variant)
        key_lmk_hex = b"U" + hexlify(enc_key_lmk).upper()

        kcv = LMKEngine.generate_kcv(raw_key[:16]).encode("ascii")
        return ErrorCodes.SUCCESS, key_lmk_hex + key_block + kcv
