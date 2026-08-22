"""
Empirical Stress Test Harness by Challenger M3 Iteration 8 for M3 Commands.
Adversarially tests single-length scheme 'Z' keys, format '48' PIN blocks,
IBM 3624 offset verification, and CVV generation/verification in pythales/commands/pin.py
and pythales/commands/card_verify.py.
"""

import pytest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.commands.pin import (
    CAHandler, DCHandler, ECHandler, BAHandler, EEHandler,
    encrypt_pin_block, decrypt_pin_block, _decrypt_key
)
from pythales.commands.card_verify import CWHandler, CYHandler, calculate_cvv, _decrypt_cvk
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def z_keys(hsm):
    # Single-length DES keys (8 bytes = 16 hex chars)
    raw_zpk1_8 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
    raw_zpk2_8 = b"\xFE\xDC\xBA\x98\x76\x54\x32\x10"
    raw_pvk_8 = b"\x12\x34\x56\x78\x90\xAB\xCD\xEF"
    raw_cvk_8 = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11"

    # Encrypt 8-byte keys under LMK
    zpk1_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk1_8, variant=2)
    zpk2_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk2_8, variant=2)
    pvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_pvk_8, variant=3)
    cvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_cvk_8, variant=4)

    # Scheme 'Z' key strings (1 scheme + 16 hex = 17 chars)
    zpk1_z_str = "Z" + hexlify(zpk1_enc).decode("ascii").upper()
    zpk2_z_str = "Z" + hexlify(zpk2_enc).decode("ascii").upper()
    pvk_z_str = "Z" + hexlify(pvk_enc).decode("ascii").upper()
    cvk_z_str = "Z" + hexlify(cvk_enc).decode("ascii").upper()

    # Double-length DES keys (16 bytes) for reference comparison
    raw_zpk1_16 = raw_zpk1_8 * 2
    raw_pvk_16 = raw_pvk_8 * 2
    raw_cvk_16 = raw_cvk_8 * 2

    zpk1_u_str = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(raw_zpk1_16, variant=2)).decode("ascii").upper()
    pvk_u_str = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(raw_pvk_16, variant=3)).decode("ascii").upper()
    cvk_u_str = "U" + hexlify(hsm.lmk_engine.encrypt_under_lmk(raw_cvk_16, variant=4)).decode("ascii").upper()

    return {
        "raw_zpk1_8": raw_zpk1_8,
        "raw_zpk2_8": raw_zpk2_8,
        "raw_pvk_8": raw_pvk_8,
        "raw_cvk_8": raw_cvk_8,
        "zpk1_z_str": zpk1_z_str,
        "zpk2_z_str": zpk2_z_str,
        "pvk_z_str": pvk_z_str,
        "cvk_z_str": cvk_z_str,
        "raw_zpk1_16": raw_zpk1_16,
        "raw_pvk_16": raw_pvk_16,
        "raw_cvk_16": raw_cvk_16,
        "zpk1_u_str": zpk1_u_str,
        "pvk_u_str": pvk_u_str,
        "cvk_u_str": cvk_u_str,
    }


# ============================================================================
# Section 1: Single-Length Scheme 'Z' Key Stress Tests
# ============================================================================

def test_scheme_z_pin_block_01_decrypt(z_keys):
    """
    Stress test: Decrypting format '01' PIN block with 8-byte scheme 'Z' key.
    Tests if DES3.new handles 8-byte keys or raises ValueError.
    """
    pan = "4000123456789010"
    pin = "1234"
    enc_pb = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan)

    key_bytes_8 = z_keys["raw_zpk1_8"]
    try:
        dec_pin = decrypt_pin_block(key_bytes_8, enc_pb, "01", pan)
        assert dec_pin == pin
    except ValueError as exc:
        pytest.fail(f"BUG-Z-01: decrypt_pin_block raised ValueError with 8-byte scheme Z key: {exc}")


def test_scheme_z_pin_block_01_encrypt(z_keys):
    """
    Stress test: Encrypting format '01' PIN block with 8-byte scheme 'Z' key.
    Tests if DES3.new handles 8-byte keys or raises ValueError.
    """
    pan = "4000123456789010"
    pin = "4321"
    key_bytes_8 = z_keys["raw_zpk1_8"]
    try:
        enc_pb = encrypt_pin_block(key_bytes_8, pin, "01", pan)
        assert len(enc_pb) == 16
    except ValueError as exc:
        pytest.fail(f"BUG-Z-02: encrypt_pin_block raised ValueError with 8-byte scheme Z key: {exc}")


def test_scheme_z_ca_pin_translate(hsm, z_keys):
    """
    Stress test: CA command translating PIN block using Scheme 'Z' keys.
    """
    pan = "4000123456789010"
    pin = "9876"
    enc_pb = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan)

    payload = f"{z_keys['zpk1_z_str']}{z_keys['zpk2_z_str']}12{enc_pb}0101{pan}".encode("ascii")
    ca_handler = CAHandler(hsm)
    try:
        err, resp = ca_handler.handle_payload(payload)
        assert err == ErrorCodes.SUCCESS
    except Exception as exc:
        pytest.fail(f"BUG-Z-03: CA handler crashed with Scheme Z keys: {exc}")


def test_scheme_z_dc_pin_verify(hsm, z_keys):
    """
    Stress test: DC command verifying PIN using Scheme 'Z' TPK and PVK keys.
    """
    pan = "4000123456789010"
    pin = "1234"
    pvki = "1"

    from pythales.crypto.tools import get_visa_pvv
    pvk_hex = hexlify(z_keys["raw_pvk_16"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan)

    payload = f"{z_keys['zpk1_z_str']}{z_keys['pvk_z_str']}{enc_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    dc_handler = DCHandler(hsm)
    try:
        err, _ = dc_handler.handle_payload(payload)
        assert err == ErrorCodes.SUCCESS
    except Exception as exc:
        pytest.fail(f"BUG-Z-04: DC handler crashed with Scheme Z keys: {exc}")


def test_scheme_z_cw_short_payload_under_33_chars(hsm, z_keys):
    """
    Stress test: CW command with Scheme 'Z' key where total payload < 33 chars.
    Key: 17 chars. PAN: 12 chars. EXP: 2 chars. Total length = 31 chars (< 33).
    """
    pan = "400012345678"  # 12 digits
    exp = "25"           # 2 digits YY
    svc = "101"          # 3 digits
    payload_31 = f"{z_keys['cvk_z_str']}{pan}{exp}{svc}".encode("ascii")  # len = 17+12+2+3 = 34
    # Let's make it 31 chars: key(17) + pan(12) + exp(2) = 31 chars
    payload_under_33 = f"{z_keys['cvk_z_str']}{pan}{exp}".encode("ascii")  # len = 31
    cw_handler = CWHandler(hsm)
    try:
        err, resp = cw_handler.handle_payload(payload_under_33)
        assert err == ErrorCodes.SUCCESS
    except PayShieldException as exc:
        if exc.error_code == ErrorCodes.INVALID_DATA_LENGTH:
            pytest.fail(f"BUG-Z-05: CW handler rejected valid Scheme Z payload (len 31) as INVALID_DATA_LENGTH: {exc}")
        else:
            raise


def test_scheme_z_cy_short_payload_under_36_chars(hsm, z_keys):
    """
    Stress test: CY command with Scheme 'Z' key where total payload < 36 chars.
    Key: 17 chars. CVV: 3 chars. PAN: 12 chars. EXP: 2 chars. Total length = 34 chars (< 36).
    """
    cvv = "123"
    pan = "400012345678"  # 12 digits
    exp_svc = "25101"    # 5 digits
    payload_34 = f"{z_keys['cvk_z_str']}{cvv}{pan}{exp_svc}".encode("ascii")  # len = 17+3+12+2 = 34
    cy_handler = CYHandler(hsm)
    try:
        err, _ = cy_handler.handle_payload(payload_34)
        assert err in (ErrorCodes.SUCCESS, ErrorCodes.LMK_ERROR)
    except PayShieldException as exc:
        if exc.error_code == ErrorCodes.INVALID_DATA_LENGTH:
            pytest.fail(f"BUG-Z-06: CY handler rejected Scheme Z payload (len 34) as INVALID_DATA_LENGTH: {exc}")
        else:
            raise


# ============================================================================
# Section 2: Format '48' PIN Block & PAN Length Edge Cases
# ============================================================================

def test_ca_translation_13_digit_pan(hsm, z_keys):
    """
    Stress test: CA command translating from format 01 to format 48 with 13-digit PAN.
    Checks if CAHandler correctly recognizes 13-digit PAN.
    """
    pan_13 = "4000123456789"  # 13 digits
    pin = "5678"
    enc_pb_01 = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan_13)

    payload = f"{z_keys['zpk1_u_str']}{z_keys['zpk1_u_str']}12{enc_pb_01}0148{pan_13}".encode("ascii")
    ca_handler = CAHandler(hsm)
    err, resp = ca_handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:-2]
    dst_fmt = resp_str[-2:]

    if dst_fmt != "48":
        pytest.fail(f"BUG-PAN-13: CAHandler failed to parse 13-digit PAN for format 48. Got dst_fmt='{dst_fmt}' instead of '48'")

    dec_pin = decrypt_pin_block(z_keys["raw_zpk1_16"], dst_pb, "48", pan_13)
    assert dec_pin == pin


def test_ca_translation_14_and_17_digit_pan(hsm, z_keys):
    """
    Stress test: CA command translation with 14-digit and 17-digit PANs.
    """
    for pan in ("40001234567890", "40001234567890123"):
        pin = "1357"
        enc_pb_01 = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan)
        payload = f"{z_keys['zpk1_u_str']}{z_keys['zpk1_u_str']}12{enc_pb_01}0148{pan}".encode("ascii")
        ca_handler = CAHandler(hsm)
        err, resp = ca_handler.handle_payload(payload)
        assert err == ErrorCodes.SUCCESS
        resp_str = resp.decode("ascii")
        dst_fmt = resp_str[-2:]
        if dst_fmt != "48":
            pytest.fail(f"BUG-PAN-{len(pan)}: CAHandler failed to parse {len(pan)}-digit PAN for format 48. Got dst_fmt='{dst_fmt}'")


# ============================================================================
# Section 3: IBM 3624 PIN Offset Verification (EE / EF)
# ============================================================================

def test_ee_ibm_offset_verification_8byte_pvk(hsm, z_keys):
    """
    Stress test: EE handler with 8-byte scheme 'Z' PVK key.
    Tests if pvk_bytes.ljust(16, b'\\x00') alters natural PIN calculation vs doubled key.
    """
    pan = "4000123456789010"
    pin = "4321"
    dec_table = "0123456789012345"

    enc_pb = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", pan)

    # First calculate expected offset using double-length key
    val_bytes = unhexlify(pan[:16])
    cipher_16 = Crypto.Cipher.DES3.new(z_keys["raw_pvk_16"], Crypto.Cipher.DES3.MODE_ECB)
    enc_val_hex = hexlify(cipher_16.encrypt(val_bytes[:8])).decode("ascii").upper()
    nat_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
    offset = "".join([str((int(pin[i]) - int(nat_pin[i])) % 10) for i in range(4)])

    # Call EE handler with Scheme Z PVK (8 bytes)
    payload_z = f"{z_keys['zpk1_u_str']}{z_keys['pvk_z_str']}{enc_pb}01{pan};{dec_table}{offset}".encode("ascii")
    ee_handler = EEHandler(hsm)
    try:
        err, _ = ee_handler.handle_payload(payload_z)
        if err != ErrorCodes.SUCCESS:
            pytest.fail("BUG-EE-01: EE handler failed IBM offset verification with Scheme Z 8-byte PVK due to zero-padding instead of key doubling")
    except Exception as exc:
        pytest.fail(f"BUG-EE-02: EE handler crashed with Scheme Z PVK: {exc}")


def test_ee_non_hex_validation_data_error_handling(hsm, z_keys):
    """
    Stress test: EE handler with non-hex account number / validation data.
    Verifies if unhandled binascii error is raised.
    """
    pin = "1234"
    enc_pb = encrypt_pin_block(z_keys["raw_zpk1_16"], pin, "01", "4000123456789010")
    # Send invalid account number with non-hex chars 'G'
    payload = f"{z_keys['zpk1_u_str']}{z_keys['pvk_u_str']}{enc_pb}01400012345678GGGG;01234567890123450000".encode("ascii")
    ee_handler = EEHandler(hsm)
    try:
        err, _ = ee_handler.handle_payload(payload)
        # Should return an error code, not crash with unhandled Python binascii exception
        assert err != ErrorCodes.SUCCESS
    except Exception as exc:
        if type(exc).__name__ in ("Error", "ValueError"):
            pytest.fail(f"BUG-EE-03: EE handler crashed with unhandled exception on non-hex data: {type(exc).__name__}: {exc}")
        else:
            raise


# ============================================================================
# Section 4: CVV Generation & Verification (CW / CX, CY / CZ)
# ============================================================================

def test_cw_cy_track2_and_semicolon_formats(hsm, z_keys):
    """
    Stress test: CW and CY with semicolon-delimited fields and track2 format.
    """
    pan = "4532012345678901"
    exp = "2608"
    svc = "101"

    cw_handler = CWHandler(hsm)
    cy_handler = CYHandler(hsm)

    # CW format 1: PAN;EXP;SVC
    cw_payload1 = f"{z_keys['cvk_u_str']}{pan};{exp};{svc}".encode("ascii")
    err1, resp1 = cw_handler.handle_payload(cw_payload1)
    assert err1 == ErrorCodes.SUCCESS
    cvv1 = resp1.decode("ascii")
    assert len(cvv1) == 3

    # CY format 1: PAN;EXP;SVC;CVV
    cy_payload1 = f"{z_keys['cvk_u_str']}{pan};{exp};{svc};{cvv1}".encode("ascii")
    err_cy1, _ = cy_handler.handle_payload(cy_payload1)
    assert err_cy1 == ErrorCodes.SUCCESS

    # CY format 2: CVV;PAN=EXPSVC
    cy_payload2 = f"{z_keys['cvk_u_str']}{cvv1};{pan}={exp}{svc}".encode("ascii")
    err_cy2, _ = cy_handler.handle_payload(cy_payload2)
    assert err_cy2 == ErrorCodes.SUCCESS

    # CY format 3: Mismatched CVV -> expect LMK_ERROR ('01')
    cy_payload_bad = f"{z_keys['cvk_u_str']}{pan};{exp};{svc};999".encode("ascii")
    err_cy_bad, _ = cy_handler.handle_payload(cy_payload_bad)
    assert err_cy_bad == ErrorCodes.LMK_ERROR
