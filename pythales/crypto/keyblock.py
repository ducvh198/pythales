"""
TR-31 / Thales Key Block Header Parser and CMAC/CBC Key Wrapping Engine.
"""

from dataclasses import dataclass
from typing import Union, Tuple, Optional
from binascii import hexlify, unhexlify
import struct

import Crypto.Cipher.DES3
import Crypto.Cipher.AES
import pythales.compat
from pythales.core.errors import PayShieldException, ErrorCodes


@dataclass
class TR31Header:
    version_id: str         # 'A', 'B', 'D', '1', 'S', 'U', 'T', 'X', 'Y'
    key_length: int         # Total length or payload length
    key_usage: str          # '00', '21' (ZPK), '52' (CVK), '71' (MAC), 'C0' (ZMK), 'P0', etc.
    algorithm: str          # 'T' (3DES), 'A' (AES), 'R' (RSA)
    mode_of_use: str        # 'B' (Enc/Dec), 'E' (Encrypt), 'D' (Decrypt), 'C' (MAC), 'N'
    key_version: str        # '00' - '99'
    exportability: str      # 'N' (Non-exportable), 'E' (Exportable), 'S' (Sensitive)
    optional_headers: bytes = b""

    def to_ascii(self) -> str:
        num_opt_blocks = 0
        if self.optional_headers:
            opt_str = self.optional_headers.decode("ascii", errors="ignore") if isinstance(self.optional_headers, bytes) else str(self.optional_headers)
            pos = 0
            while pos + 4 <= len(opt_str):
                opt_id = opt_str[pos:pos+2]
                len_str = opt_str[pos+2:pos+4]
                if opt_id.isalnum() and all(c in "0123456789ABCDEFabcdef" for c in len_str):
                    try:
                        data_bytes_len = int(len_str, 16)
                        block_len = 4 + data_bytes_len * 2
                        pos += block_len
                        num_opt_blocks += 1
                    except ValueError:
                        break
                else:
                    break
        opt_count = f"{num_opt_blocks:02d}"
        reserved = "00"
        hdr_16 = (
            f"{self.version_id}"
            f"{self.key_length:04d}"
            f"{self.key_usage}"
            f"{self.algorithm}"
            f"{self.mode_of_use}"
            f"{self.key_version}"
            f"{self.exportability}"
            f"{opt_count}"
            f"{reserved}"
        )
        if self.optional_headers:
            if isinstance(self.optional_headers, bytes):
                hdr_16 += self.optional_headers.decode("ascii", errors="ignore")
            else:
                hdr_16 += str(self.optional_headers)
        return hdr_16


def parse_header(header_ascii: Union[str, bytes]) -> TR31Header:
    """
    Parse TR-31 / Thales Key Block header ASCII string or bytes.
    Header format (minimum 16 characters):
    [0]: Version ID ('S', 'A', 'B', 'D', '1', 'U', 'T', 'X', 'Y')
    [1:5]: Key Length (4 digits int)
    [5:7]: Key Usage (2 chars, e.g. '00', '21', '52', '71', 'C0')
    [7]: Algorithm ('T', 'A', 'R')
    [8]: Mode of Use ('B', 'E', 'D', 'C', 'V', 'N')
    [9:11]: Key Version ('00')
    [11]: Exportability ('N', 'E', 'S')
    [12:14]: Optional Header Count ('00')
    [14:16]: Reserved ('00')
    """
    hdr_str = header_ascii.decode("ascii", errors="ignore") if isinstance(header_ascii, bytes) else str(header_ascii)
    if len(hdr_str) < 16:
        raise PayShieldException(
            ErrorCodes.INVALID_KEY_BLOCK,
            f"TR-31 header must be at least 16 characters, got {len(hdr_str)}"
        )

    version_id = hdr_str[0]
    try:
        key_length = int(hdr_str[1:5])
    except ValueError:
        raise PayShieldException(
            ErrorCodes.INVALID_KEY_BLOCK,
            f"Invalid key length in header: '{hdr_str[1:5]}'"
        )

    key_usage = hdr_str[5:7]
    algorithm = hdr_str[7]
    mode_of_use = hdr_str[8]
    key_version = hdr_str[9:11]
    exportability = hdr_str[11]
    opt_count_str = hdr_str[12:14]

    try:
        num_opts = int(opt_count_str)
    except ValueError:
        try:
            num_opts = int(opt_count_str, 16)
        except ValueError:
            num_opts = 0

    if num_opts == 0:
        optional_headers = b""
    else:
        pos = 16
        blocks_parsed = 0
        while blocks_parsed < num_opts and pos + 4 <= len(hdr_str):
            opt_id = hdr_str[pos:pos+2]
            len_str = hdr_str[pos+2:pos+4]
            if not opt_id.isalnum() or not all(c in "0123456789ABCDEFabcdef" for c in len_str):
                break
            try:
                data_bytes_len = int(len_str, 16)
            except ValueError:
                break
            block_len = 4 + data_bytes_len * 2
            if pos + block_len > len(hdr_str):
                break
            pos += block_len
            blocks_parsed += 1

        optional_headers = hdr_str[16:pos].encode("ascii") if pos > 16 else b""

    return TR31Header(
        version_id=version_id,
        key_length=key_length,
        key_usage=key_usage,
        algorithm=algorithm,
        mode_of_use=mode_of_use,
        key_version=key_version,
        exportability=exportability,
        optional_headers=optional_headers
    )


class TR31KeyBlock:
    @staticmethod
    def parse_header(header_ascii: Union[str, bytes]) -> TR31Header:
        return parse_header(header_ascii)

    @staticmethod
    def _derive_keys(kbmk: bytes, algorithm: str = "T") -> Tuple[bytes, bytes]:
        """
        Derive Encryption Key (K_enc) and MAC Key (K_mac) from Key Block Binding Master Key (kbmk).
        """
        if len(kbmk) not in (16, 24, 32):
            raise PayShieldException(ErrorCodes.INVALID_KEY_LENGTH, f"Invalid KBMK length: {len(kbmk)} bytes")

        # Key derivation using XOR masks on KBMK for 3DES and AES
        mask_enc = b"\x01" * len(kbmk)
        mask_mac = b"\x02" * len(kbmk)

        k_enc = bytes(a ^ b for a, b in zip(kbmk, mask_enc))
        k_mac = bytes(a ^ b for a, b in zip(kbmk, mask_mac))
        return k_enc, k_mac

    @staticmethod
    def wrap(key_bytes: bytes, header: Union[TR31Header, str, bytes], kbmk: bytes) -> bytes:
        """
        Wrap clear key bytes into TR-31 Key Block bytes.
        """
        if isinstance(header, (str, bytes)):
            hdr_obj = parse_header(header)
        else:
            hdr_obj = header

        k_enc, k_mac = TR31KeyBlock._derive_keys(kbmk, hdr_obj.algorithm)

        # Build payload: 2-byte key length in bits + key_bytes + padding
        key_bits = len(key_bytes) * 8
        payload = struct.pack(">H", key_bits) + key_bytes

        block_size = 16 if hdr_obj.algorithm == "A" else 8
        pad_len = block_size - (len(payload) % block_size)
        if pad_len != block_size:
            payload += b"\x00" * pad_len

        # Encrypt payload
        if hdr_obj.algorithm == "A" or len(k_enc) == 32:
            cipher = Crypto.Cipher.AES.new(k_enc[:16], Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
        else:
            cipher = Crypto.Cipher.DES3.new(k_enc[:16] if len(k_enc) == 16 else k_enc[:24], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)

        enc_payload = cipher.encrypt(payload)
        enc_payload_hex = hexlify(enc_payload).upper()

        opt_len = len(hdr_obj.optional_headers) if hdr_obj.optional_headers else 0
        mac_len_hex = 16
        total_block_len = 16 + opt_len + len(enc_payload_hex) + mac_len_hex
        hdr_obj.key_length = total_block_len

        hdr_ascii = hdr_obj.to_ascii()
        hdr_bytes = hdr_ascii.encode("ascii")

        # MAC calculation over Header ASCII + Encrypted Payload HEX
        mac_data = hdr_bytes + enc_payload_hex

        if hdr_obj.algorithm == "A" or len(k_mac) == 32:
            mac_cipher = Crypto.Cipher.AES.new(k_mac[:16], Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
            mac_pad = 16 - (len(mac_data) % 16)
            if mac_pad != 16:
                mac_data += b"\x00" * mac_pad
            mac_out = mac_cipher.encrypt(mac_data)[-16:]
            mac_hex = hexlify(mac_out[:8]).upper()
        else:
            mac_cipher = Crypto.Cipher.DES3.new(k_mac[:16] if len(k_mac) == 16 else k_mac[:24], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
            mac_pad = 8 - (len(mac_data) % 8)
            if mac_pad != 8:
                mac_data += b"\x00" * mac_pad
            mac_out = mac_cipher.encrypt(mac_data)[-8:]
            mac_hex = hexlify(mac_out).upper()

        key_block = hdr_bytes + enc_payload_hex + mac_hex
        return key_block

    @staticmethod
    def unwrap(key_block: Union[bytes, str], kbmk: bytes) -> Tuple[TR31Header, bytes]:
        """
        Unwrap TR-31 Key Block and return tuple of (TR31Header, clear_key_bytes).
        """
        kb_str = key_block.decode("ascii", errors="ignore") if isinstance(key_block, bytes) else str(key_block)
        if len(kb_str) < 32:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, f"Key block length too short: {len(kb_str)}")

        hdr_obj = parse_header(kb_str)
        header_len = 16 + (len(hdr_obj.optional_headers) if hdr_obj.optional_headers else 0)
        hdr_str = kb_str[:header_len]

        mac_len_hex = 16 if (hdr_obj.algorithm == "A" or len(kbmk) == 32) else 16  # 8 bytes = 16 hex chars
        if len(kb_str) < header_len + mac_len_hex:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Key block corrupted or missing MAC")

        enc_payload_hex_str = kb_str[header_len:-mac_len_hex]
        if not enc_payload_hex_str or len(enc_payload_hex_str) % 2 != 0:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Payload hex length must be non-empty and even")

        try:
            enc_payload = unhexlify(enc_payload_hex_str)
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Invalid hex characters in encrypted payload")

        enc_payload_hex = enc_payload_hex_str.encode("ascii")
        mac_hex = kb_str[-mac_len_hex:].upper()

        k_enc, k_mac = TR31KeyBlock._derive_keys(kbmk, hdr_obj.algorithm)

        # Verify MAC over full header ASCII + enc_payload_hex
        mac_data = hdr_str.encode("ascii") + enc_payload_hex

        if hdr_obj.algorithm == "A" or len(k_mac) == 32:
            mac_cipher = Crypto.Cipher.AES.new(k_mac[:16], Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
            mac_pad = 16 - (len(mac_data) % 16)
            if mac_pad != 16:
                mac_data += b"\x00" * mac_pad
            mac_out = mac_cipher.encrypt(mac_data)[-16:]
            expected_mac_hex = hexlify(mac_out[:8]).upper().decode("ascii")
        else:
            mac_cipher = Crypto.Cipher.DES3.new(k_mac[:16] if len(k_mac) == 16 else k_mac[:24], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
            mac_pad = 8 - (len(mac_data) % 8)
            if mac_pad != 8:
                mac_data += b"\x00" * mac_pad
            mac_out = mac_cipher.encrypt(mac_data)[-8:]
            expected_mac_hex = hexlify(mac_out).upper().decode("ascii")

        if mac_hex != expected_mac_hex:
            raise PayShieldException(
                ErrorCodes.INVALID_KEY_CHECK_VALUE,
                f"TR-31 Key Block MAC mismatch: expected '{expected_mac_hex}', got '{mac_hex}'"
            )

        # Decrypt payload
        if hdr_obj.algorithm == "A" or len(k_enc) == 32:
            cipher = Crypto.Cipher.AES.new(k_enc[:16], Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
        else:
            cipher = Crypto.Cipher.DES3.new(k_enc[:16] if len(k_enc) == 16 else k_enc[:24], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)

        try:
            dec_payload = cipher.decrypt(enc_payload)
        except Exception as e:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, f"Payload decryption failed: {e}")

        if len(dec_payload) < 2:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Decrypted payload too short")

        try:
            key_bits = struct.unpack(">H", dec_payload[:2])[0]
        except Exception:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Invalid header in decrypted payload")

        key_bytes_len = key_bits // 8

        if len(dec_payload) < 2 + key_bytes_len or key_bytes_len <= 0:
            raise PayShieldException(ErrorCodes.INVALID_KEY_BLOCK, "Decrypted payload truncated or invalid key length")

        clear_key = dec_payload[2:2 + key_bytes_len]
        return hdr_obj, clear_key
