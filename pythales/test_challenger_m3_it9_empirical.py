"""
Empirical Adversarial Test Suite for Milestone M3 (PIN & Card Verification Commands - Iteration 9).
Target commands: CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ.
Empirically demonstrates bugs in key scheme processing ('D', 'E', 'A') and _extract_key_string heuristic truncation.
"""

import pytest
import struct
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.lmk import LMKEngine
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header
from pythales.commands.pin import (
    _decrypt_key,
    decrypt_pin_block,
    encrypt_pin_block,
    _extract_pin_block_and_fmt,
    _parse_pan_and_pvv,
)
from pythales.commands.card_verify import _decrypt_cvk, calculate_cvv
from pythales.commands.key_mgmt import _extract_key_string


@pytest.fixture
def hsm():
    return HSM(header="1234")


# ============================================================================
# HELPER FUNCTIONS FOR PROTOCOL PACKING / PARSING
# ============================================================================

def struct_pack_req(header: bytes, cmd: bytes, data: bytes) -> bytes:
    payload = header + cmd + data
    length = len(payload)
    return struct.pack("!H", length) + payload


def parse_resp(resp_bytes: bytes):
    """
    Parses HSM response body returned by process_raw_message.
    Body format: [Header (4 bytes)] + [Response Code (2 bytes)] + [Error Code (2 bytes)] + [Response Data]
    """
    header = resp_bytes[:4]
    resp_code = resp_bytes[4:6].decode("ascii")
    error_code = resp_bytes[6:8].decode("ascii")
    resp_data = resp_bytes[8:]
    return header, resp_code, error_code, resp_data


# ============================================================================
# 1. KEY EXTRACTION & HEURISTIC TRUNCATION EMPIRICAL BUGS
# ============================================================================

def test_extract_key_string_heuristic_truncation_bug():
    """
    Demonstrates empirical bug in _extract_key_string (key_mgmt.py:44).
    When payload following a 33-char Scheme 'U' key starts with format codes '48', '01', '02', '03', '04', '05', or '99'
    followed by digits, _extract_key_string falsely truncates the 33-char key to 17 chars.
    """
    key_33 = "UFB46B43C0E41200885E63495D49205E9"  # 33 chars Scheme 'U' key
    
    # 1. When payload after key starts with CVV '485' + PAN '4532012345678901'
    payload_485 = key_33 + "4854532012345678901;2711101"
    extracted_key_485, rem_485 = _extract_key_string(payload_485)
    assert len(extracted_key_485) == 33, f"Expected 33 chars, got {len(extracted_key_485)} ('{extracted_key_485}')"
    assert extracted_key_485 == key_33

    # 2. When payload after key starts with CVV '012' + PAN '4532012345678901'
    payload_012 = key_33 + "0124532012345678901;2711101"
    extracted_key_012, rem_012 = _extract_key_string(payload_012)
    assert len(extracted_key_012) == 33, f"Expected 33 chars, got {len(extracted_key_012)} ('{extracted_key_012}')"

    # 3. When payload after key starts with CVV '999' + PAN '4532012345678901'
    payload_999 = key_33 + "9994532012345678901;2711101"
    extracted_key_999, rem_999 = _extract_key_string(payload_999)
    assert len(extracted_key_999) == 33, f"Expected 33 chars, got {len(extracted_key_999)} ('{extracted_key_999}')"


def test_key_scheme_D_extraction_and_decryption(hsm):
    """
    Stress test Scheme 'D' (double-length key, 33 chars: 'D' + 32 hex).
    Tests whether _extract_key_string and _decrypt_key correctly handle 33-char Scheme 'D' keys
    without truncating to 17 chars or corrupting subsequent payload fields.
    """
    clear_key = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
    enc_key = hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=2)
    enc_hex = hexlify(enc_key).decode("ascii").upper()
    key_str_D = "D" + enc_hex  # 33 characters

    # 1. Check extraction length
    extracted_key, rem = _extract_key_string(key_str_D + ";REMAINING")
    assert len(extracted_key) == 33, f"Expected 33-char key string for Scheme 'D', got {len(extracted_key)} chars ('{extracted_key}')"
    assert extracted_key == key_str_D
    assert rem == ";REMAINING", f"Expected remaining string ';REMAINING', got '{rem}'"

    # 2. Check decrypted key byte length
    dec_key = _decrypt_key(hsm, key_str_D, variant=2)
    assert len(dec_key) == 16, f"Expected 16 bytes for Scheme 'D' double-length key, got {len(dec_key)}"
    assert dec_key == clear_key


def test_key_scheme_E_extraction_and_decryption(hsm):
    """
    Stress test Scheme 'E' (triple-length key, 49 chars: 'E' + 48 hex).
    """
    clear_key = b"\x01" * 24
    enc_key = hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=2)
    enc_hex = hexlify(enc_key).decode("ascii").upper()
    key_str_E = "E" + enc_hex  # 49 characters

    extracted_key, rem = _extract_key_string(key_str_E + ";REMAINING")
    assert len(extracted_key) == 49, f"Expected 49-char key string for Scheme 'E', got {len(extracted_key)} chars ('{extracted_key}')"
    assert extracted_key == key_str_E
    assert rem == ";REMAINING"

    dec_key = _decrypt_key(hsm, key_str_E, variant=2)
    assert len(dec_key) == 24, f"Expected 24 bytes for Scheme 'E' triple-length key, got {len(dec_key)}"
    assert dec_key == clear_key


def test_key_scheme_A_extraction_and_decryption(hsm):
    """
    Stress test Scheme 'A' (double-length key, 33 chars: 'A' + 32 hex).
    """
    clear_key = b"\x02" * 16
    enc_key = hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=2)
    enc_hex = hexlify(enc_key).decode("ascii").upper()
    key_str_A = "A" + enc_hex  # 33 characters

    extracted_key, rem = _extract_key_string(key_str_A + ";REMAINING")
    assert len(extracted_key) == 33, f"Expected 33-char key string for Scheme 'A', got {len(extracted_key)} chars ('{extracted_key}')"
    assert extracted_key == key_str_A
    assert rem == ";REMAINING"

    dec_key = _decrypt_key(hsm, key_str_A, variant=2)
    assert len(dec_key) == 16, f"Expected 16 bytes for Scheme 'A' double-length key, got {len(dec_key)}"
    assert dec_key == clear_key


def test_card_verify_key_scheme_D_E_A_decryption(hsm):
    """
    Stress test _decrypt_cvk in card_verify.py for Schemes 'D', 'E', 'A'.
    """
    clear_key_16 = b"\x11" * 16
    enc_key_16 = hsm.lmk_engine.encrypt_under_lmk(clear_key_16, variant=4)
    enc_hex_16 = hexlify(enc_key_16).decode("ascii").upper()

    cvk_D = _decrypt_cvk(hsm, "D" + enc_hex_16)
    assert len(cvk_D) == 16, f"Expected 16 bytes for _decrypt_cvk Scheme 'D', got {len(cvk_D)}"
    assert cvk_D == clear_key_16

    cvk_A = _decrypt_cvk(hsm, "A" + enc_hex_16)
    assert len(cvk_A) == 16, f"Expected 16 bytes for _decrypt_cvk Scheme 'A', got {len(cvk_A)}"
    assert cvk_A == clear_key_16

    clear_key_24 = b"\x22" * 24
    enc_key_24 = hsm.lmk_engine.encrypt_under_lmk(clear_key_24, variant=4)
    enc_hex_24 = hexlify(enc_key_24).decode("ascii").upper()

    cvk_E = _decrypt_cvk(hsm, "E" + enc_hex_24)
    assert len(cvk_E) == 24, f"Expected 24 bytes for _decrypt_cvk Scheme 'E', got {len(cvk_E)}"
    assert cvk_E == clear_key_24


# ============================================================================
# 2. CA / CB PIN TRANSLATION ADVERSARIAL TESTS
# ============================================================================

def test_ca_translation_format0_to_format4(hsm):
    """
    Test CA PIN translation from Format 0 (DES) to Format 4 (AES).
    """
    zpk1_raw = b"\x10" * 16
    zpk2_raw = b"\x20" * 16
    zpk1_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk1_raw, variant=2)).decode("ascii").upper()
    zpk2_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk2_raw, variant=2)).decode("ascii").upper()

    pan = "4111111111111111"
    pin = "4321"

    src_pin_block = encrypt_pin_block(zpk1_raw, pin, "01", pan)
    
    # Request: CA + zpk1 + zpk2 + max_pin_len + src_block + src_fmt + dst_fmt + pan
    req_data = (zpk1_enc + zpk2_enc + "12" + src_pin_block + "01" + "48" + pan).encode("ascii")
    raw_req = struct_pack_req(b"1234", b"CA", req_data)

    raw_resp = hsm.process_raw_message(raw_req)
    header, resp_code, error_code, resp_data = parse_resp(raw_resp)

    assert resp_code == "CB"
    assert error_code == ErrorCodes.SUCCESS
    
    # Decrypt returned Format 4 PIN block using zpk2
    dst_pin_block = resp_data[:32].decode("ascii")
    dec_pin = decrypt_pin_block(zpk2_raw, dst_pin_block, "48", pan)
    assert dec_pin == pin


def test_ca_max_pin_length_enforcement(hsm):
    """
    Test CA rejecting PINs whose length exceeds max_pin_len parameter with '23'.
    """
    zpk_raw = b"\x15" * 16
    zpk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk_raw, variant=2)).decode("ascii").upper()
    pan = "1234567890123456"
    pin_6 = "123456"
    src_block = encrypt_pin_block(zpk_raw, pin_6, "01", pan)

    # Set max_pin_len = 04 (exceeded by 6-digit PIN)
    req_data = (zpk_enc + zpk_enc + "04" + src_block + "01" + "01" + pan).encode("ascii")
    raw_req = struct_pack_req(b"1234", b"CA", req_data)

    raw_resp = hsm.process_raw_message(raw_req)
    _, resp_code, error_code, resp_data = parse_resp(raw_resp)

    assert resp_code == "CB"
    assert error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE  # '23'
    assert len(resp_data) == 0  # Truncation rule


# ============================================================================
# 3. DC / DD AND EC / ED PIN VERIFICATION TESTS
# ============================================================================

def test_dc_pin_verification_success_and_mismatch(hsm):
    """
    Test DC command (Verify Customer PIN) with Visa PVV method.
    """
    tpk_raw = b"\x30" * 16
    pvk_raw = b"\x40" * 16
    tpk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(tpk_raw, variant=2)).decode("ascii").upper()
    pvk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(pvk_raw, variant=3)).decode("ascii").upper()

    pan = "4000123456789010"
    pin = "1234"
    pvki = "1"

    # Compute expected PVV using pynblock get_visa_pvv
    from pynblock.tools import get_visa_pvv
    pvv_bytes = get_visa_pvv(
        pan.encode("ascii"),
        pvki.encode("ascii"),
        pin.encode("ascii"),
        hexlify(pvk_raw).decode("ascii").upper().encode("ascii")
    )
    pvv_str = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(tpk_raw, pin, "01", pan)

    # Valid verification request
    req_data = (tpk_enc + pvk_enc + pin_block + "01" + pan + ";" + pvki + pvv_str).encode("ascii")
    raw_req = struct_pack_req(b"1234", b"DC", req_data)

    raw_resp = hsm.process_raw_message(raw_req)
    _, resp_code, error_code, _ = parse_resp(raw_resp)

    assert resp_code == "DD"
    assert error_code == ErrorCodes.SUCCESS

    # Mismatched PVV request
    wrong_pvv = "9999" if pvv_str != "9999" else "0000"
    req_data_bad = (tpk_enc + pvk_enc + pin_block + "01" + pan + ";" + pvki + wrong_pvv).encode("ascii")
    raw_req_bad = struct_pack_req(b"1234", b"DC", req_data_bad)

    raw_resp_bad = hsm.process_raw_message(raw_req_bad)
    _, resp_code_bad, error_code_bad, _ = parse_resp(raw_resp_bad)

    assert resp_code_bad == "DD"
    assert error_code_bad == ErrorCodes.LMK_ERROR  # '01' mismatch


# ============================================================================
# 4. BA / BB ENCRYPT CLEAR PIN AND RANDOM GENERATION TESTS
# ============================================================================

def test_ba_encrypt_clear_pin_with_delimiters(hsm):
    """
    Test BA command encrypting explicit clear PIN with ';' and 'F' delimiters.
    """
    zpk_raw = b"\x50" * 16
    zpk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk_raw, variant=2)).decode("ascii").upper()
    pan = "4111111111111111"
    pin = "7890"

    # With ';' delimiter
    req_data_semi = (zpk_enc + pan + ";" + pin).encode("ascii")
    raw_req = struct_pack_req(b"1234", b"BA", req_data_semi)
    raw_resp = hsm.process_raw_message(raw_req)
    _, resp_code, error_code, resp_data = parse_resp(raw_resp)

    assert resp_code == "BB"
    assert error_code == ErrorCodes.SUCCESS
    returned_pin = resp_data[:4].decode("ascii")
    returned_block = resp_data[4:].decode("ascii")
    assert returned_pin == pin
    dec_pin = decrypt_pin_block(zpk_raw, returned_block, "01", pan)
    assert dec_pin == pin

    # With 'F' delimiter
    req_data_f = (zpk_enc + pan + "F" + pin).encode("ascii")
    raw_req_f = struct_pack_req(b"1234", b"BA", req_data_f)
    raw_resp_f = hsm.process_raw_message(raw_req_f)
    _, resp_code_f, error_code_f, resp_data_f = parse_resp(raw_resp_f)

    assert resp_code_f == "BB"
    assert error_code_f == ErrorCodes.SUCCESS
    assert resp_data_f[:4].decode("ascii") == pin


# ============================================================================
# 5. EE / EF IBM 3624 PIN OFFSET VERIFICATION TESTS
# ============================================================================

def test_ee_ibm3624_verification_and_short_decimal_table(hsm):
    """
    Test EE command with valid offset and test short decimalization table error ('15').
    """
    zpk_raw = b"\x60" * 16
    pvk_raw = b"\x70" * 16
    zpk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk_raw, variant=2)).decode("ascii").upper()
    pvk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(pvk_raw, variant=3)).decode("ascii").upper()

    pan = "1234567890123456"
    pin = "5555"

    pin_block = encrypt_pin_block(zpk_raw, pin, "01", pan)

    # Short decimalization table (< 16 chars) must raise INVALID_DATA_LENGTH ('15')
    short_table = "0123456789"
    req_data_short = (zpk_enc + pvk_enc + pin_block + "01" + pan + ";" + short_table + "0000").encode("ascii")
    raw_req_short = struct_pack_req(b"1234", b"EE", req_data_short)

    raw_resp_short = hsm.process_raw_message(raw_req_short)
    _, resp_code_short, error_code_short, resp_data_short = parse_resp(raw_resp_short)

    assert resp_code_short == "EF"
    assert error_code_short == ErrorCodes.INVALID_DATA_LENGTH  # '15'
    assert len(resp_data_short) == 0


# ============================================================================
# 6. CW / CX AND CY / CZ CARD VERIFICATION TESTS
# ============================================================================

def test_cw_cy_roundtrip_with_track2_layouts(hsm):
    """
    Test CW CVV generation and CY CVV verification roundtrip across Track 2 layouts.
    """
    cvk_raw = b"\x80" * 16
    cvk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(cvk_raw, variant=4)).decode("ascii").upper()

    pan = "4111111111111111"
    exp_date = "2612"
    service_code = "101"

    # Generate CVV via CW handler
    cvv_calc = calculate_cvv(cvk_raw, pan, exp_date, service_code)
    assert len(cvv_calc) == 3 and cvv_calc.isdigit()

    # CW command request
    req_cw = (cvk_enc + pan + ";" + exp_date + ";" + service_code).encode("ascii")
    raw_cw = struct_pack_req(b"1234", b"CW", req_cw)
    raw_resp_cw = hsm.process_raw_message(raw_cw)
    _, resp_code_cw, error_code_cw, resp_data_cw = parse_resp(raw_resp_cw)

    assert resp_code_cw == "CX"
    assert error_code_cw == ErrorCodes.SUCCESS
    assert resp_data_cw.decode("ascii") == cvv_calc

    # CY command request (CVV first: CVV;PAN;EXP;SVC)
    req_cy1 = (cvk_enc + cvv_calc + ";" + pan + ";" + exp_date + ";" + service_code).encode("ascii")
    raw_cy1 = struct_pack_req(b"1234", b"CY", req_cy1)
    raw_resp_cy1 = hsm.process_raw_message(raw_cy1)
    _, resp_code_cy1, error_code_cy1, _ = parse_resp(raw_resp_cy1)

    assert resp_code_cy1 == "CZ"
    assert error_code_cy1 == ErrorCodes.SUCCESS

    # CY command request (Track 2 format: PAN=EXPSVC;CVV)
    req_cy2 = (cvk_enc + pan + "=" + exp_date + service_code + ";" + cvv_calc).encode("ascii")
    raw_cy2 = struct_pack_req(b"1234", b"CY", req_cy2)
    raw_resp_cy2 = hsm.process_raw_message(raw_cy2)
    _, resp_code_cy2, error_code_cy2, _ = parse_resp(raw_resp_cy2)

    assert resp_code_cy2 == "CZ"
    assert error_code_cy2 == ErrorCodes.SUCCESS


# ============================================================================
# 7. MALFORMED / INVALID PIN BLOCK HANDLING TESTS
# ============================================================================

def test_invalid_pin_block_hex_rejection(hsm):
    """
    Test that invalid/non-hex PIN block raises INVALID_PIN_BLOCK ('21') and truncates response data.
    """
    zpk_raw = b"\x90" * 16
    zpk_enc = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(zpk_raw, variant=2)).decode("ascii").upper()
    pan = "1234567890123456"

    # Non-hex PIN block string "ZZZZZZZZZZZZZZZZ"
    req_data = (zpk_enc + zpk_enc + "12" + "ZZZZZZZZZZZZZZZZ" + "01" + "01" + pan).encode("ascii")
    raw_req = struct_pack_req(b"1234", b"CA", req_data)

    raw_resp = hsm.process_raw_message(raw_req)
    _, resp_code, error_code, resp_data = parse_resp(raw_resp)

    assert resp_code == "CB"
    assert error_code == ErrorCodes.INVALID_PIN_BLOCK  # '21'
    assert len(resp_data) == 0
