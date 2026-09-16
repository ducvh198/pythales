"""
Adversarial Challenger Test Suite for M2 (Iteration 4).
Focuses on empirical stress testing of key management commands, TR-31 optional header handling,
KCV consistency, DEK protection, PCI key separation, MAC verification, and framing truncation.
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
# 1. TR-31 Optional Header Parsing & Multi-Block Wrap/Unwrap
# =====================================================================

def test_tr31_optional_headers_single_block():
    kbmk = os.urandom(16)
    clear_key = os.urandom(16)
    opt_header_bytes = b"PB0100"  # PB = 2 chars, len = 01 (1 byte = 2 hex chars '00')
    hdr = TR31Header(
        version_id="S",
        key_length=80,
        key_usage="21",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E",
        optional_headers=opt_header_bytes
    )
    wrapped = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
    unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(wrapped, kbmk)

    assert unwrapped_key == clear_key
    assert unwrapped_hdr.optional_headers == opt_header_bytes


def test_tr31_optional_headers_multi_block():
    kbmk = os.urandom(16)
    clear_key = os.urandom(16)
    # Block 1: PB0100 (len 6)
    # Block 2: HM0411223344 (len 4 + 4*2 = 12)
    opt_header_bytes = b"PB0100HM0411223344"
    hdr = TR31Header(
        version_id="S",
        key_length=90,
        key_usage="C0",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E",
        optional_headers=opt_header_bytes
    )
    wrapped = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
    unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(wrapped, kbmk)

    assert unwrapped_key == clear_key
    assert unwrapped_hdr.optional_headers == opt_header_bytes


def test_tr31_opt_count_zero_with_payload_matching_opt_pattern():
    """Verify that opt_count == '00' ignores any optional header pattern in ciphertext."""
    kbmk = os.urandom(16)
    clear_key = b"\xAF\x10\x04\x11" + os.urandom(12)
    hdr = TR31Header(
        version_id="S",
        key_length=80,
        key_usage="21",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E"
    )
    wrapped = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
    # Confirm opt_count is "00"
    assert wrapped[12:14] == b"00"
    unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(wrapped, kbmk)

    assert unwrapped_hdr.optional_headers == b""
    assert unwrapped_key == clear_key


# =====================================================================
# 2. Comprehensive Key Management Commands (A0, BU, A2/A4, A6, GI, KW)
# =====================================================================

def test_a0_all_schemes_and_key_types(hsm):
    schemes = ["U", "T", "S", "X", "Y"]
    key_types = ["000", "001", "002", "003", "005", "00A", "00B", "402"]

    for kt in key_types:
        for sch in schemes:
            req = make_request(b"A0", f"0{kt}{sch}".encode("ascii"))
            resp = hsm.process_raw_message(req)
            frame = MessageFraming.parse_request(resp, header_length=4)
            assert frame.command_code == "A1"
            assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
            res_str = frame.raw_body[4:].decode("ascii")
            kcv = res_str[-6:]
            assert len(kcv) == 6
            assert all(c in "0123456789ABCDEF" for c in kcv)


def test_bu_kcv_verification_for_all_types_and_schemes(hsm):
    schemes = ["U", "T", "S", "X", "Y"]
    key_types = ["000", "001", "002", "003", "005", "00A", "00B", "402"]

    for kt in key_types:
        for sch in schemes:
            # Generate key first
            a0_req = make_request(b"A0", f"0{kt}{sch}".encode("ascii"))
            a0_resp = hsm.process_raw_message(a0_req)
            a0_frame = MessageFraming.parse_request(a0_resp, header_length=4)
            a0_body = a0_frame.raw_body[4:].decode("ascii")
            key_lmk = a0_body[:-6]
            expected_kcv = a0_body[-6:]

            # BU with 3-digit key type
            bu_req = make_request(b"BU", f"{kt}{key_lmk}".encode("ascii"))
            bu_resp = hsm.process_raw_message(bu_req)
            bu_frame = MessageFraming.parse_request(bu_resp, header_length=4)
            assert bu_frame.command_code == "BV"
            assert bu_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
            assert bu_frame.raw_body[4:].decode("ascii") == expected_kcv


def test_a2_a4_component_roundtrip_3_comps(hsm):
    # A2 3 components for 3DES triple-length ('T')
    a2_req = make_request(b"A2", b"1001T")
    a2_resp = hsm.process_raw_message(a2_req)
    a2_frame = MessageFraming.parse_request(a2_resp, header_length=4)
    assert a2_frame.command_code == "A3"
    assert a2_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

    body = a2_frame.raw_body[4:].decode("ascii")
    key_lmk = body[:49]
    kcv = body[49:55]
    comp1 = body[55:104]
    comp2 = body[104:153]
    comp3 = body[153:202]

    # A4 form 3 components
    a4_payload = f"3001T{comp1}{comp2}{comp3}".encode("ascii")
    a4_req = make_request(b"A4", a4_payload)
    a4_resp = hsm.process_raw_message(a4_req)
    a4_frame = MessageFraming.parse_request(a4_resp, header_length=4)
    assert a4_frame.command_code == "A5"
    assert a4_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

    a4_body = a4_frame.raw_body[4:].decode("ascii")
    formed_key_lmk = a4_body[:49]
    formed_kcv = a4_body[49:55]

    assert formed_key_lmk == key_lmk
    assert formed_kcv == kcv


def test_a6_import_under_tr31_zmk(hsm):
    # Step 1: Generate ZMK as TR-31 key block under LMK
    zmk_req = make_request(b"A0", b"0000S")
    zmk_resp = hsm.process_raw_message(zmk_req)
    zmk_frame = MessageFraming.parse_request(zmk_resp, header_length=4)
    zmk_kb = zmk_frame.raw_body[4:].decode("ascii")[:-6]

    # Unwrap ZMK clear key for local wrapping
    hdr, zmk_raw = TR31KeyBlock.unwrap(zmk_kb, hsm.LMK)

    # Step 2: Create a ZPK wrapped under ZMK in TR-31 format
    zpk_raw = os.urandom(16)
    zpk_hdr = TR31Header("S", 80, "21", "T", "B", "00", "E")
    zpk_tr31 = TR31KeyBlock.wrap(zpk_raw, zpk_hdr, zmk_raw).decode("ascii")

    # Step 3: A6 import ZPK under TR-31 ZMK into LMK (target scheme 'U')
    a6_payload = f"001{zmk_kb}{zpk_tr31}U".encode("ascii")
    a6_req = make_request(b"A6", a6_payload)
    a6_resp = hsm.process_raw_message(a6_req)
    a6_frame = MessageFraming.parse_request(a6_resp, header_length=4)

    assert a6_frame.command_code == "A7"
    assert a6_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    res_str = a6_frame.raw_body[4:].decode("ascii")
    key_u = res_str[:33]
    kcv = res_str[33:39]

    assert kcv == LMKEngine.generate_kcv(zpk_raw)
    dec_zpk = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_u[1:]), variant=2)
    assert dec_zpk == zpk_raw


def test_a6_rejects_transport_only_target_scheme_E(hsm):
    # Generate ZMK under LMK (scheme U)
    zmk_req = make_request(b"A0", b"0000U")
    zmk_resp = hsm.process_raw_message(zmk_req)
    zmk_frame = MessageFraming.parse_request(zmk_resp, header_length=4)
    zmk_hex = zmk_frame.raw_body[4:].decode("ascii")[:33]
    zmk_raw = hsm.lmk_engine.decrypt_under_lmk(unhexlify(zmk_hex[1:]), variant=1)

    # 16-byte ZPK encrypted under ZMK ECB
    zpk_16 = os.urandom(16)
    cipher = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    zpk_zmk_hex = "U" + hexlify(cipher.encrypt(zpk_16)).upper().decode("ascii")

    # A6 import with target scheme 'E'
    a6_payload = f"001{zmk_hex}{zpk_zmk_hex}E".encode("ascii")
    a6_req = make_request(b"A6", a6_payload)
    a6_resp = hsm.process_raw_message(a6_req)
    a6_frame = MessageFraming.parse_request(a6_resp, header_length=4)

    assert a6_frame.command_code == "A7"
    assert a6_frame.raw_body[2:4].decode("ascii") == ErrorCodes.INVALID_KEY_SCHEME


def test_gi_roundtrip_all_key_types(hsm):
    key_types = ["000", "001", "002", "003", "005", "00A", "402"]

    for kt in key_types:
        raw_key = os.urandom(16)
        var = KEY_TYPE_VARIANTS[kt]
        enc_lmk = hsm.lmk_engine.encrypt_under_lmk(raw_key, variant=var)
        key_u = "U" + hexlify(enc_lmk).upper().decode("ascii")

        # Translate U -> S
        gi_req1 = make_request(b"GI", f"{kt}US{key_u}".encode("ascii"))
        gi_resp1 = hsm.process_raw_message(gi_req1)
        f1 = MessageFraming.parse_request(gi_resp1, header_length=4)
        assert f1.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
        tr31_kb = f1.raw_body[4:].decode("ascii")[:-6]

        # Translate S -> U
        gi_req2 = make_request(b"GI", f"{kt}SU{tr31_kb}".encode("ascii"))
        gi_resp2 = hsm.process_raw_message(gi_req2)
        f2 = MessageFraming.parse_request(gi_resp2, header_length=4)
        assert f2.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
        key_u_2 = f2.raw_body[4:].decode("ascii")[:-6]

        dec_key = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_u_2[1:]), variant=var)
        assert dec_key == raw_key


def test_kw_aes_key_generation(hsm):
    # KBMK AES key block under LMK
    kbmk_req = make_request(b"A0", b"0000S")
    kbmk_resp = hsm.process_raw_message(kbmk_req)
    kbmk_frame = MessageFraming.parse_request(kbmk_resp, header_length=4)
    kbmk_kb = kbmk_frame.raw_body[4:].decode("ascii")[:-6]

    # Header for AES key (Algorithm 'A')
    aes_hdr = "S0096C0AB00E0000"
    kw_payload = f"000{kbmk_kb}{aes_hdr}".encode("ascii")
    kw_req = make_request(b"KW", kw_payload)
    kw_resp = hsm.process_raw_message(kw_req)
    kw_frame = MessageFraming.parse_request(kw_resp, header_length=4)

    assert kw_frame.command_code == "KX"
    assert kw_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    res_str = kw_frame.raw_body[4:].decode("ascii")
    key_lmk = res_str[:33]
    kcv = res_str[-6:]
    tr31_block = res_str[33:-6]

    _, kbmk_raw = TR31KeyBlock.unwrap(kbmk_kb, hsm.LMK)
    parsed_hdr, clear_key = TR31KeyBlock.unwrap(tr31_block, kbmk_raw)

    assert parsed_hdr.algorithm == "A"
    assert len(clear_key) == 32
    assert LMKEngine.generate_kcv(clear_key[:16]) == kcv


# =====================================================================
# 3. Error Code Truncation Rule Verification
# =====================================================================

def test_framing_error_truncation_rule(hsm):
    # Invalid key type in A0 returns error '02'
    req = make_request(b"A0", b"0999U")
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)

    # Frame header must be b"1234" and raw_body must be response code (A1) + error code (02) = 4 bytes
    assert frame.header_bytes == b"1234"
    assert frame.raw_body == b"A104"
    # Response Data post Error Code must be empty (truncated)
    assert frame.raw_body[4:] == b""


def test_framing_error_truncation_all_error_codes(hsm):
    error_payloads = [
        (b"A0", b"0999U", b"A1", ErrorCodes.INVALID_KEY_TYPE),
        (b"A0", b"0000Z", b"A1", ErrorCodes.INVALID_KEY_SCHEME),
        (b"BU", b"999U11223344556677889900AABBCCDDEEFF", b"BV", ErrorCodes.INVALID_KEY_TYPE),
    ]

    for cmd, payload, expected_resp_code, expected_err_code in error_payloads:
        req = make_request(cmd, payload)
        resp = hsm.process_raw_message(req)
        frame = MessageFraming.parse_request(resp, header_length=4)
        assert frame.command_code == expected_resp_code.decode("ascii")
        assert frame.raw_body[2:4].decode("ascii") == expected_err_code
        # Truncation check: Response Data post Error Code MUST be empty (length of raw_body is exactly 4)
        assert len(frame.raw_body) == 4
        assert frame.raw_body[4:] == b""


# =====================================================================
# 4. Deep Edge Case Stress Tests (NC, NO, A0 Mode 1 TR-31, BU TR-31, A2/A4 X/Y, A6 S, GI 3-Key, KW 3-Key)
# =====================================================================

def test_diagnostics_nc_empty_header():
    hsm_no_hdr = HSM()
    req = b"\x00\x02NC"
    resp = hsm_no_hdr.process_raw_message(req)
    assert resp.startswith(b"ND00")
    assert len(resp) == 2 + 2 + 16 + 9  # ND (2) + 00 (2) + 16 (KCV) + 9 (firmware)


def test_diagnostics_no_echo_binary_and_4kb_payload(hsm):
    # Binary non-ASCII bytes (excluding delimiter 0x19)
    bin_data = bytes(i for i in range(256) if i != 0x19)
    req_bin = make_request(b"NO", bin_data)
    resp_bin = hsm.process_raw_message(req_bin)
    frame_bin = MessageFraming.parse_request(resp_bin, header_length=4)
    assert frame_bin.command_code == "NP"
    assert frame_bin.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    assert frame_bin.raw_body[4:] == bin_data

    # 4KB payload (excluding delimiter 0x19)
    large_data = os.urandom(4096).replace(b"\x19", b"\x18")
    req_large = make_request(b"NO", large_data)
    resp_large = hsm.process_raw_message(req_large)
    frame_large = MessageFraming.parse_request(resp_large, header_length=4)
    assert frame_large.command_code == "NP"
    assert frame_large.raw_body[4:] == large_data


def test_a0_mode_1_export_under_tr31_zmk(hsm):
    # Step 1: Generate ZMK as TR-31 Key Block
    zmk_req = make_request(b"A0", b"0000S")
    zmk_resp = hsm.process_raw_message(zmk_req)
    zmk_frame = MessageFraming.parse_request(zmk_resp, header_length=4)
    zmk_kb = zmk_frame.raw_body[4:].decode("ascii")[:-6]

    # Step 2: A0 Mode 1 export ZPK under TR-31 ZMK
    payload = f"1001U;0{zmk_kb}".encode("ascii")
    req = make_request(b"A0", payload)
    resp = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp, header_length=4)

    assert frame.command_code == "A1"
    assert frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    body_str = frame.raw_body[4:].decode("ascii")
    key_lmk = body_str[:33]
    key_zmk = body_str[33:-6]
    kcv = body_str[-6:]

    # Verify key_zmk decrypts using ZMK clear key
    _, zmk_raw = TR31KeyBlock.unwrap(zmk_kb, hsm.LMK)
    dec_zpk_lmk = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_lmk[1:]), variant=2)
    cipher_zmk = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    dec_zpk_zmk = cipher_zmk.decrypt(unhexlify(key_zmk[1:]))

    assert dec_zpk_lmk == dec_zpk_zmk
    assert LMKEngine.generate_kcv(dec_zpk_lmk) == kcv


def test_bu_tr31_key_block_input(hsm):
    # Generate ZPK as TR-31 key block
    gen_req = make_request(b"A0", b"0001S")
    gen_resp = hsm.process_raw_message(gen_req)
    gen_frame = MessageFraming.parse_request(gen_resp, header_length=4)
    gen_body = gen_frame.raw_body[4:].decode("ascii")
    tr31_kb = gen_body[:-6]
    expected_kcv = gen_body[-6:]

    # BU with TR-31 Key Block
    bu_req = make_request(b"BU", f"001{tr31_kb}".encode("ascii"))
    bu_resp = hsm.process_raw_message(bu_req)
    bu_frame = MessageFraming.parse_request(bu_resp, header_length=4)

    assert bu_frame.command_code == "BV"
    assert bu_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    assert bu_frame.raw_body[4:].decode("ascii") == expected_kcv


def test_a2_a4_component_roundtrip_schemes_X_and_Y(hsm):
    for sch in ("X", "Y"):
        comp_len = 49 if sch == "Y" else 33
        a2_req = make_request(b"A2", f"0001{sch}".encode("ascii"))
        a2_frame = MessageFraming.parse_request(hsm.process_raw_message(a2_req), header_length=4)
        assert a2_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

        body = a2_frame.raw_body[4:].decode("ascii")
        key_lmk = body[:comp_len]
        kcv = body[comp_len:comp_len+6]
        c1 = body[comp_len+6:comp_len*2+6]
        c2 = body[comp_len*2+6:comp_len*3+6]

        a4_req = make_request(b"A4", f"2001{sch}{c1}{c2}".encode("ascii"))
        a4_frame = MessageFraming.parse_request(hsm.process_raw_message(a4_req), header_length=4)
        assert a4_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS

        a4_body = a4_frame.raw_body[4:].decode("ascii")
        assert a4_body[:comp_len] == key_lmk
        assert a4_body[comp_len:comp_len+6] == kcv


def test_a6_target_scheme_S_returns_tr31(hsm):
    zmk_req = make_request(b"A0", b"0000U")
    zmk_frame = MessageFraming.parse_request(hsm.process_raw_message(zmk_req), header_length=4)
    zmk_hex = zmk_frame.raw_body[4:].decode("ascii")[:33]
    zmk_raw = hsm.lmk_engine.decrypt_under_lmk(unhexlify(zmk_hex[1:]), variant=1)

    zpk_16 = os.urandom(16)
    cipher = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    zpk_zmk_hex = "U" + hexlify(cipher.encrypt(zpk_16)).upper().decode("ascii")

    a6_payload = f"001{zmk_hex}{zpk_zmk_hex}S".encode("ascii")
    a6_req = make_request(b"A6", a6_payload)
    a6_frame = MessageFraming.parse_request(hsm.process_raw_message(a6_req), header_length=4)

    assert a6_frame.command_code == "A7"
    assert a6_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    res_str = a6_frame.raw_body[4:].decode("ascii")
    kcv = res_str[-6:]
    tr31_kb = res_str[:-6]

    assert tr31_kb.startswith("S")
    assert kcv == LMKEngine.generate_kcv(zpk_16)
    _, unwrapped_zpk = TR31KeyBlock.unwrap(tr31_kb, hsm.LMK)
    assert unwrapped_zpk == zpk_16


def test_kw_3des_3key_generation(hsm):
    # Generate 3-key 3DES KBMK under LMK (scheme 'T')
    kbmk_req = make_request(b"A0", b"0000T")
    kbmk_frame = MessageFraming.parse_request(hsm.process_raw_message(kbmk_req), header_length=4)
    kbmk_hex = kbmk_frame.raw_body[4:].decode("ascii")[:49]

    header_str = "S008021TB00E0000"
    kw_req = make_request(b"KW", f"001{kbmk_hex}{header_str}".encode("ascii"))
    kw_frame = MessageFraming.parse_request(hsm.process_raw_message(kw_req), header_length=4)

    assert kw_frame.command_code == "KX"
    assert kw_frame.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    res_str = kw_frame.raw_body[4:].decode("ascii")
    key_lmk = res_str[:33]
    kcv = res_str[-6:]
    tr31_kb = res_str[33:-6]

    kbmk_raw = hsm.lmk_engine.decrypt_under_lmk(unhexlify(kbmk_hex[1:]), variant=1)
    _, clear_key = TR31KeyBlock.unwrap(tr31_kb, kbmk_raw)

    assert LMKEngine.generate_kcv(clear_key) == kcv
    dec_key_lmk = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_lmk[1:]), variant=2)
    assert dec_key_lmk == clear_key
