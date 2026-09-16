"""
Adversarial Re-verification Stress Test Suite for Milestone M2.
Tests TR-31 Key Block wrapping/unwrapping, key management commands (A0, A2, A4, A6, BU, GI, KW, NC, NO),
DEK protection, PCI key separation, dynamic ZMK slicing, and edge-case exception handling.
"""

import pytest
import os
import struct
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
import Crypto.Cipher.AES

from pythales.hsm import HSM
from pythales.core.frame import MessageFraming
from pythales.core.errors import PayShieldException, ErrorCodes
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header, parse_header
from pythales.crypto.lmk import LMKEngine
from pythales.commands.key_mgmt import _extract_key_string, KEY_TYPE_VARIANTS


@pytest.fixture
def hsm():
    return HSM(header="1234")


def make_request(cmd: bytes, payload: bytes = b"", header: bytes = b"1234") -> bytes:
    body = header + cmd + payload
    return struct.pack("!H", len(body)) + body


# =====================================================================
# 1. TR-31 Key Block Algorithm Variations & Header Edge Cases
# =====================================================================

def test_tr31_3des_2key_and_3key_wrap_unwrap():
    # 2-key 3DES (16 bytes KBMK)
    kbmk_16 = os.urandom(16)
    key_16 = os.urandom(16)
    hdr_t = TR31Header("S", 80, "21", "T", "B", "00", "E")
    kb_16 = TR31KeyBlock.wrap(key_16, hdr_t, kbmk_16)
    parsed_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb_16, kbmk_16)
    assert parsed_hdr.key_usage == "21"
    assert unwrapped_key == key_16

    # 3-key 3DES (24 bytes KBMK)
    kbmk_24 = os.urandom(24)
    key_24 = os.urandom(24)
    kb_24 = TR31KeyBlock.wrap(key_24, hdr_t, kbmk_24)
    _, unwrapped_key_24 = TR31KeyBlock.unwrap(kb_24, kbmk_24)
    assert unwrapped_key_24 == key_24


def test_tr31_aes_wrap_unwrap():
    kbmk_aes = os.urandom(16)
    key_aes = os.urandom(32)
    hdr_a = TR31Header("S", 80, "C0", "A", "B", "00", "E")
    kb_aes = TR31KeyBlock.wrap(key_aes, hdr_a, kbmk_aes)
    parsed_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb_aes, kbmk_aes)
    assert parsed_hdr.algorithm == "A"
    assert unwrapped_key == key_aes


def test_tr31_unwrap_wrong_kbmk_raises_10():
    kbmk_1 = os.urandom(16)
    kbmk_2 = os.urandom(16)
    clear_key = os.urandom(16)
    hdr = TR31Header("S", 80, "21", "T", "B", "00", "E")
    kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk_1)

    with pytest.raises(PayShieldException) as exc:
        TR31KeyBlock.unwrap(kb, kbmk_2)
    assert exc.value.error_code == ErrorCodes.INVALID_KEY_CHECK_VALUE  # '10'


# =====================================================================
# 2. Dynamic Key Extraction Slicing (_extract_key_string)
# =====================================================================

def test_extract_key_string_schemes():
    # Scheme U / X (33 chars)
    u_str = "U" + "1" * 32 + "EXTRA"
    key, rem = _extract_key_string(u_str)
    assert key == "U" + "1" * 32
    assert rem == "EXTRA"

    # Scheme T / Y (49 chars)
    t_str = "T" + "2" * 48 + "EXTRA"
    key, rem = _extract_key_string(t_str)
    assert key == "T" + "2" * 48
    assert rem == "EXTRA"

    # Scheme S (TR-31 block with 80 characters)
    s_hdr = "S008021TB00E0000" + "A" * 64
    s_str = s_hdr + "TRAILING_DATA"
    key, rem = _extract_key_string(s_str)
    assert key == s_hdr
    assert rem == "TRAILING_DATA"


def test_extract_key_string_invalid_scheme():
    with pytest.raises(PayShieldException) as exc:
        _extract_key_string("Q1122334455667788")
    assert exc.value.error_code == ErrorCodes.INVALID_KEY_SCHEME  # '12'


def test_extract_key_string_incomplete():
    with pytest.raises(PayShieldException) as exc:
        _extract_key_string("U11223344")
    assert exc.value.error_code == ErrorCodes.INVALID_DATA_LENGTH  # '15'


# =====================================================================
# 3. A0 Key Generation Edge Cases & Invalid Types
# =====================================================================

def test_a0_all_valid_key_types_and_schemes(hsm):
    schemes = ["U", "T", "S", "X", "Y"]
    types = list(KEY_TYPE_VARIANTS.keys())

    for kt in types:
        for sch in schemes:
            req = make_request(b"A0", f"0{kt}{sch}".encode("ascii"))
            resp = hsm.process_raw_message(req)
            frame = MessageFraming.parse_request(resp, header_length=4)
            assert frame.command_code == "A1"
            err = frame.raw_body[2:4].decode("ascii")
            assert err == ErrorCodes.SUCCESS, f"Failed for key_type={kt}, scheme={sch}"


def test_a0_mode1_zmk_export_scheme_U(hsm):
    zmk_req = make_request(b"A0", b"0000U")
    zmk_resp = hsm.process_raw_message(zmk_req)
    zmk_frame = MessageFraming.parse_request(zmk_resp, header_length=4)
    zmk_hex = zmk_frame.raw_body[4:].decode("ascii")[:33]

    payload = f"1001U;0{zmk_hex}".encode("ascii")
    req = make_request(b"A0", payload)
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)
    assert frame.command_code == "A1"
    err = frame.raw_body[2:4].decode("ascii")
    assert err == ErrorCodes.SUCCESS
    kcv = frame.raw_body[4:].decode("ascii")[-6:]
    assert len(kcv) == 6


def test_a0_invalid_key_type_returns_02(hsm):
    req = make_request(b"A0", b"0999U")
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)
    err = frame.raw_body[2:4].decode("ascii")
    assert err == ErrorCodes.INVALID_KEY_TYPE  # '02'


def test_a0_invalid_mode_returns_15(hsm):
    req = make_request(b"A0", b"9000U")
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)
    err = frame.raw_body[2:4].decode("ascii")
    assert err == ErrorCodes.INVALID_DATA_LENGTH  # '15'


# =====================================================================
# 4. BU KCV Handler Edge Cases
# =====================================================================

def test_bu_2digit_and_3digit_key_types(hsm):
    a0_req = make_request(b"A0", b"0001U")
    a0_resp = hsm.process_raw_message(a0_req)
    a0_frame = MessageFraming.parse_request(a0_resp, header_length=4)
    key_u = a0_frame.raw_body[4:].decode("ascii")[:33]
    expected_kcv = a0_frame.raw_body[4:].decode("ascii")[33:39]

    # Test BU with 3-digit '001'
    bu_3_req = make_request(b"BU", f"001{key_u}".encode("ascii"))
    bu_3_frame = MessageFraming.parse_request(hsm.process_raw_message(bu_3_req), header_length=4)
    assert bu_3_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    assert bu_3_frame.raw_body[4:].decode("ascii") == expected_kcv

    # Test BU with 2-digit '01'
    bu_2_req = make_request(b"BU", f"01{key_u}".encode("ascii"))
    bu_2_frame = MessageFraming.parse_request(hsm.process_raw_message(bu_2_req), header_length=4)
    assert bu_2_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    assert bu_2_frame.raw_body[4:].decode("ascii") == expected_kcv


def test_bu_invalid_key_type_returns_02(hsm):
    bu_req = make_request(b"BU", b"999U11223344556677889900AABBCCDDEEFF")
    bu_frame = MessageFraming.parse_request(hsm.process_raw_message(bu_req), header_length=4)
    assert bu_frame.raw_body[2:4].decode("ascii") == ErrorCodes.INVALID_KEY_TYPE


# =====================================================================
# 5. A2 & A4 Component Generation and Formation Roundtrip
# =====================================================================

def test_a2_a4_component_roundtrip_2_comps(hsm):
    # Step 1: A2 generate 2 components for ZPK (Scheme U)
    a2_req = make_request(b"A2", b"0001U")
    a2_resp = hsm.process_raw_message(a2_req)
    a2_frame = MessageFraming.parse_request(a2_resp, header_length=4)
    assert a2_frame.command_code == "A3"
    assert a2_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

    a2_body = a2_frame.raw_body[4:].decode("ascii")
    key_lmk = a2_body[:33]
    kcv = a2_body[33:39]
    comp1 = a2_body[39:72]
    comp2 = a2_body[72:105]

    # Step 2: A4 form key from components
    a4_payload = f"2001U{comp1}{comp2}".encode("ascii")
    a4_req = make_request(b"A4", a4_payload)
    a4_resp = hsm.process_raw_message(a4_req)
    a4_frame = MessageFraming.parse_request(a4_resp, header_length=4)
    assert a4_frame.command_code == "A5"
    assert a4_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

    a4_body = a4_frame.raw_body[4:].decode("ascii")
    formed_key_lmk = a4_body[:33]
    formed_kcv = a4_body[33:39]

    assert formed_key_lmk == key_lmk
    assert formed_kcv == kcv


def test_a2_invalid_key_type_returns_02(hsm):
    req = make_request(b"A2", b"0999U")
    frame = MessageFraming.parse_request(hsm.process_raw_message(req), header_length=4)
    assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.INVALID_KEY_TYPE


def test_a4_missing_component_returns_15(hsm):
    req = make_request(b"A4", b"2001UU11223344556677889900AABBCCDDEEFF")
    frame = MessageFraming.parse_request(hsm.process_raw_message(req), header_length=4)
    assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.INVALID_DATA_LENGTH


# =====================================================================
# 6. KW Handler TR-31 Generation & Unwrapping Verification
# =====================================================================

def test_kw_generate_tr31_block(hsm):
    a0_req = make_request(b"A0", b"0000U")
    a0_resp = hsm.process_raw_message(a0_req)
    a0_frame = MessageFraming.parse_request(a0_resp, header_length=4)
    kbmk_u_hex = a0_frame.raw_body[4:].decode("ascii")[:33]

    header_str = "S008021TB00E0000"
    kw_payload = f"001{kbmk_u_hex}{header_str}".encode("ascii")
    kw_req = make_request(b"KW", kw_payload)
    kw_resp = hsm.process_raw_message(kw_req)
    kw_frame = MessageFraming.parse_request(kw_resp, header_length=4)
    assert kw_frame.command_code == "KX"
    assert kw_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

    resp_str = kw_frame.raw_body[4:].decode("ascii")
    key_lmk = resp_str[:33]
    kcv = resp_str[-6:]
    key_block = resp_str[33:-6]

    kbmk_raw = hsm.lmk_engine.decrypt_under_lmk(unhexlify(kbmk_u_hex[1:]), variant=1)
    _, clear_key = TR31KeyBlock.unwrap(key_block, kbmk_raw)

    assert LMKEngine.generate_kcv(clear_key) == kcv
    dec_key_lmk = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_lmk[1:]), variant=2)
    assert dec_key_lmk == clear_key


def test_kw_invalid_key_type_returns_02(hsm):
    kw_req = make_request(b"KW", b"999U11223344556677889900AABBCCDDEEFFS008021TB00E0000")
    kw_frame = MessageFraming.parse_request(hsm.process_raw_message(kw_req), header_length=4)
    assert kw_frame.raw_body[2:4].decode("ascii") == ErrorCodes.INVALID_KEY_TYPE


# =====================================================================
# 7. Diagnostics (NC & NO) Handlers
# =====================================================================

def test_diagnostics_nc(hsm):
    req = make_request(b"NC")
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)
    assert frame.command_code == "ND"
    assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    payload = frame.raw_body[4:].decode("ascii")
    assert len(payload) == 16 + 9
    assert payload.endswith("0007-E000")


def test_diagnostics_no_echo(hsm):
    echo_data = b"TEST_PAYLOAD_12345!@#$"
    req = make_request(b"NO", echo_data)
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)
    assert frame.command_code == "NP"
    assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    assert frame.raw_body[4:] == echo_data
