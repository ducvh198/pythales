"""
Adversarial Test Suite - Milestone M3 (PIN & Card Verification Commands)
Challenger 2 - Iteration 5
"""

import pytest
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock
from pythales.commands.pin import (
    encrypt_pin_block, decrypt_pin_block, CAHandler, DCHandler, ECHandler, BAHandler, EEHandler
)
from pythales.commands.card_verify import (
    calculate_cvv, CWHandler, CYHandler
)
from pythales.crypto.tools import get_visa_pvv


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def keys(hsm):
    # Scheme U (Variant 2 ZPK - 16 bytes 3DES)
    clear_zpk = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
    enc_zpk = hsm.lmk_engine.encrypt_under_lmk(clear_zpk, variant=2)
    zpk_u = "U" + hexlify(enc_zpk).decode("ascii").upper()

    # Scheme X (Variant 2 ZPK2 - 16 bytes 3DES)
    clear_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
    enc_zpk2 = hsm.lmk_engine.encrypt_under_lmk(clear_zpk2, variant=2)
    zpk2_x = "X" + hexlify(enc_zpk2).decode("ascii").upper()

    # Scheme T (Variant 2 ZPK3 - 24 bytes 3DES)
    clear_zpk3 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18"
    enc_zpk3 = hsm.lmk_engine.encrypt_under_lmk(clear_zpk3, variant=2)
    zpk3_t = "T" + hexlify(enc_zpk3).decode("ascii").upper()

    # Scheme S (TR-31 Key Block ZPK)
    tr31_zpk = TR31KeyBlock.wrap(clear_zpk, "S0048P0TD00E0000", hsm.LMK).decode("ascii")

    # Scheme U (Variant 3 PVK - 16 bytes)
    clear_pvk = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
    enc_pvk = hsm.lmk_engine.encrypt_under_lmk(clear_pvk, variant=3)
    pvk_u = "U" + hexlify(enc_pvk).decode("ascii").upper()

    # Scheme S (TR-31 Key Block PVK)
    tr31_pvk = TR31KeyBlock.wrap(clear_pvk, "S0048V0TD00E0000", hsm.LMK).decode("ascii")

    # Scheme U (Variant 4 CVK - 16 bytes)
    clear_cvk = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x11\x22\x33\x44\x55\x66\x77\x88"
    enc_cvk = hsm.lmk_engine.encrypt_under_lmk(clear_cvk, variant=4)
    cvk_u = "U" + hexlify(enc_cvk).decode("ascii").upper()

    # Scheme S (TR-31 Key Block CVK)
    tr31_cvk = TR31KeyBlock.wrap(clear_cvk, "S0048C0TD00E0000", hsm.LMK).decode("ascii")

    # AES ZPK (128-bit) for Format 4
    clear_aes_zpk = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    enc_aes_zpk = hsm.lmk_engine.encrypt_under_lmk(clear_aes_zpk, variant=2)
    aes_zpk_u = "U" + hexlify(enc_aes_zpk).decode("ascii").upper()

    return {
        "clear_zpk": clear_zpk,
        "zpk_u": zpk_u,
        "clear_zpk2": clear_zpk2,
        "zpk2_x": zpk2_x,
        "clear_zpk3": clear_zpk3,
        "zpk3_t": zpk3_t,
        "tr31_zpk": tr31_zpk,
        "clear_pvk": clear_pvk,
        "pvk_u": pvk_u,
        "tr31_pvk": tr31_pvk,
        "clear_cvk": clear_cvk,
        "cvk_u": cvk_u,
        "tr31_cvk": tr31_cvk,
        "clear_aes_zpk": clear_aes_zpk,
        "aes_zpk_u": aes_zpk_u,
    }


# ============================================================================
# 1. Test Format 0 vs Format 4 PIN Block Encryption / Decryption with 19-digit PAN
# ============================================================================

def test_pin_block_format0_19digit_pan(hsm, keys):
    pan = "4123456789012345678"  # 19 digits
    pin = "987654"
    block_hex = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    assert len(block_hex) == 16
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], block_hex, "01", pan)
    assert decrypted_pin == pin


def test_pin_block_format4_19digit_pan(hsm, keys):
    pan = "4123456789012345678"  # 19 digits
    pin = "12345678"
    block_hex = encrypt_pin_block(keys["clear_aes_zpk"], pin, "48", pan)
    assert len(block_hex) == 32
    decrypted_pin = decrypt_pin_block(keys["clear_aes_zpk"], block_hex, "48", pan)
    assert decrypted_pin == pin


# ============================================================================
# 2. Test CA Command with TR-31 Key Blocks & Scheme Cross-Translation
# ============================================================================

def test_ca_tr31_to_scheme_x_translation(hsm, keys):
    pan = "4575272222567122"
    pin = "4321"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["tr31_zpk"] + keys["zpk2_x"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    out_fmt = resp_str[16:]
    assert out_fmt == "01"
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin


# ============================================================================
# 3. Test DC Command with TR-31 PVK Key Block
# ============================================================================

def test_dc_tr31_pvk_verification(hsm, keys):
    pan = "4575272222567122"
    pin = "1234"
    pvki = "1"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["tr31_pvk"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 4. Test EC Command with Format 4 AES PIN Block and TR-31 Keys
# ============================================================================

def test_ec_format4_tr31_pvk_verification(hsm, keys):
    pan = "4575272222567122"
    pin = "8765"
    pvki = "3"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_aes_zpk"], pin, "48", pan)
    payload = (keys["aes_zpk_u"] + keys["tr31_pvk"] + pin_block + "48" + pan + ";" + pvki + pvv).encode("ascii")
    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 5. Test CW and CY Commands with TR-31 CVK and Track 2 '=' layout
# ============================================================================

def test_cw_tr31_cvk_track2_layout(hsm, keys):
    pan = "4575272222567122"
    exp = "2612"
    svc = "101"
    track2 = f"{pan}={exp}{svc}9999"
    payload = (keys["tr31_cvk"] + track2).encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    cvv = resp.decode("ascii")
    assert len(cvv) == 3
    expected_cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    assert cvv == expected_cvv


def test_cy_tr31_cvk_track2_layout(hsm, keys):
    pan = "4575272222567122"
    exp = "2612"
    svc = "101"
    cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    track2_with_cvv = f"{cvv};{pan}={exp}{svc}9999"
    payload = (keys["tr31_cvk"] + track2_with_cvv).encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 6. Test Invalid PIN Block Format Code Exception Handling
# ============================================================================

def test_invalid_pin_block_format_code(keys):
    with pytest.raises(PayShieldException) as exc_info:
        encrypt_pin_block(keys["clear_zpk"], "1234", "99", "4575272222567122")
    assert exc_info.value.error_code == ErrorCodes.INVALID_PIN_BLOCK_FORMAT
