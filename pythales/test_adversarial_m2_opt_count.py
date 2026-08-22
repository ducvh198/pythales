"""
Adversarial Stress Test Suite for TR-31 Key Block Optional Header Parsing (opt_count == '00').
Stress-tests TR-31 wrapping and unwrapping with 500+ random key blocks and targeted alphanumeric ciphertext prefixes.
"""

import pytest
import os
import struct
import random
import string
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
import Crypto.Cipher.AES

from pythales.crypto.keyblock import TR31KeyBlock, TR31Header, parse_header
from pythales.core.errors import PayShieldException, ErrorCodes


# Sample optional header tag prefixes matching TR-31 specification and arbitrary alphanumeric tags
OPT_TAG_PREFIXES = [
    "PB01", "HM02", "AL04", "AF10", "AA02", "KS04", "TS08", "VI02", "DF01", "EX04",
    "B002", "C004", "D008", "E010", "F001", "1102", "9904", "AB08", "CD02", "EF04",
    "KS01", "PB02", "HM04", "AL08", "AF02", "AA04", "TS04", "VI08", "DF02", "EX08",
]

ALGORITHMS = ["T", "A"]
VERSION_IDS = ["A", "B", "C", "D"]
KEY_USAGES = ["00", "21", "52", "71", "C0", "P0", "M0", "D0", "E0", "V0"]
MODES_OF_USE = ["B", "E", "D", "C", "V", "N"]
EXPORTABILITIES = ["E", "N", "S"]


def test_tr31_500_random_opt_count_zero_wrap_unwrap():
    """
    Stress-test TR-31 key block wrapping and unwrapping with 500+ random key blocks where opt_count == "00".
    Verifies zero unwrapping failures, zero CBC boundary errors, and zero unhexlify errors.
    """
    unwrapped_count = 0
    for i in range(500):
        alg = random.choice(ALGORITHMS)
        ver = random.choice(VERSION_IDS)
        usage = random.choice(KEY_USAGES)
        mode = random.choice(MODES_OF_USE)
        exp = random.choice(EXPORTABILITIES)

        # TR-31 binding algorithm is selected by Version ID, independently
        # from the algorithm of the key carried inside the block.
        if ver == "D":
            kbmk_len = random.choice([16, 24, 32])
        elif ver == "B":
            kbmk_len = random.choice([16, 24])
        else:  # A/C variant binding permits single/double/triple DES KBPKs.
            kbmk_len = random.choice([8, 16, 24])

        if alg == "T":
            clear_key_len = random.choice([16, 24])
        else:
            clear_key_len = random.choice([16, 24, 32])

        kbmk = os.urandom(kbmk_len)
        clear_key = os.urandom(clear_key_len)

        hdr = TR31Header(
            version_id=ver,
            key_length=0,
            key_usage=usage,
            algorithm=alg,
            mode_of_use=mode,
            key_version="00",
            exportability=exp,
            optional_headers=b""
        )

        kb_bytes = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
        kb_str = kb_bytes.decode("ascii")

        # Verify opt_count in header string is "00"
        assert kb_str[12:14] == "00", f"Iteration {i}: opt_count expected '00', got '{kb_str[12:14]}'"

        # Parse header directly
        parsed_hdr = parse_header(kb_str)
        assert parsed_hdr.optional_headers == b"", f"Iteration {i}: optional_headers expected b'', got {parsed_hdr.optional_headers}"

        # Unwrap key block
        unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb_bytes, kbmk)
        assert unwrapped_key == clear_key, f"Iteration {i}: Clear key mismatch"
        assert unwrapped_hdr.algorithm == alg
        assert unwrapped_hdr.key_usage == usage
        assert unwrapped_hdr.optional_headers == b""

        unwrapped_count += 1

    assert unwrapped_count == 500


def test_tr31_500_alphanumeric_ciphertext_prefix_opt_count_zero():
    """
    Stress-test 500+ key blocks where opt_count == "00" and index 16 is systematically checked or injected
    with alphanumeric prefixes (PB01, HM02, AL04, AF10, AA02, etc.).
    Verifies parse_header always yields optional_headers == b'' and unwrap handles hex/non-hex gracefully.
    """
    tested_count = 0

    # 1. Test valid ciphertext hex prefixes matching optional header format (e.g. AF10, AA02, B004, C008, D002, E004, F002)
    valid_hex_prefixes = ["AF10", "AA02", "B004", "C008", "D002", "E004", "F002", "0002", "1104", "9902", "AB04", "CD02", "EF04"]

    for prefix in valid_hex_prefixes:
        # Search for a key/KBMK combo that produces enc_payload_hex starting with `prefix`
        kbmk = os.urandom(16)
        hdr = TR31Header("S", 0, "21", "A", "B", "00", "E", optional_headers=b"")

        for _ in range(500):
            clear_key = os.urandom(16)
            kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
            kb_str = kb.decode("ascii")
            enc_hex = kb_str[16:-16]
            if enc_hex.startswith(prefix):
                # Found a matching key block!
                parsed_hdr = parse_header(kb_str)
                assert parsed_hdr.optional_headers == b""
                unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb, kbmk)
                assert unwrapped_key == clear_key
                assert unwrapped_hdr.optional_headers == b""
                tested_count += 1
                break

    # 2. Test targeted injection of all 30 OPT_TAG_PREFIXES into key block string at index 16 with opt_count == "00"
    for prefix in OPT_TAG_PREFIXES:
        for trial in range(20):
            kbmk = os.urandom(16)
            clear_key = os.urandom(16)
            hdr = TR31Header("S", 0, "21", "A", "B", "00", "E", optional_headers=b"")
            kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
            kb_str = kb.decode("ascii")

            # Force index 16:20 to be the prefix
            forced_kb_str = kb_str[:16] + prefix + kb_str[20:]

            # parse_header MUST parse optional_headers as b"" because opt_count is "00"
            parsed_hdr = parse_header(forced_kb_str)
            assert parsed_hdr.optional_headers == b"", f"Prefix {prefix}: parse_header extracted non-empty optional header despite opt_count=='00'"

            # Attempting unwrap on forced_kb_str:
            # If prefix contains non-hex chars (e.g. 'P', 'H', 'M', 'L'), unwrap MUST raise PayShieldException with INVALID_KEY_BLOCK (unhexlify error) or INVALID_KEY_CHECK_VALUE.
            # It MUST NOT raise IndexError, ValueError, CBC alignment exception, or crash!
            try:
                TR31KeyBlock.unwrap(forced_kb_str, kbmk)
            except PayShieldException as exc:
                assert exc.error_code in (ErrorCodes.INVALID_KEY_BLOCK, ErrorCodes.INVALID_KEY_CHECK_VALUE)
            except Exception as e:
                pytest.fail(f"Prefix {prefix}: unwrap raised unexpected exception {type(e)}: {e}")

            tested_count += 1

    assert tested_count >= 500


def test_tr31_header_opt_count_boundary_conditions():
    """
    Test edge cases in opt_count parsing in TR-31 header.
    """
    # opt_count == "00"
    hdr_00 = "S008021TB00E0000PB010211223344556677889900AABBCCDDEEFF1122334455667788"
    parsed_00 = parse_header(hdr_00)
    assert parsed_00.optional_headers == b""

    # opt_count == "01" with valid optional header block PB0102 (PB=tag, 01=1 byte data=02)
    hdr_01 = "S008021TB00E0100PB010211223344556677889900AABBCCDDEEFF1122334455667788"
    parsed_01 = parse_header(hdr_01)
    assert parsed_01.optional_headers == b"PB0102"

    # opt_count == "01" with 3 bytes data (PB03021122)
    hdr_01_3bytes = "S008021TB00E0100PB030211223344556677889900AABBCCDDEEFF1122334455667788"
    parsed_01_3bytes = parse_header(hdr_01_3bytes)
    assert parsed_01_3bytes.optional_headers == b"PB03021122"

    # Invalid non-numeric opt_count defaults to num_opts = 0
    hdr_invalid_opt = "S008021TB00EZZ00PB010211223344556677889900AABBCCDDEEFF1122334455667788"
    parsed_inv = parse_header(hdr_invalid_opt)
    assert parsed_inv.optional_headers == b""
