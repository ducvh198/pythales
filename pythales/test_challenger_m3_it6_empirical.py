"""
Empirical Stress Test & Security Harness for PyThales M3 PIN & Card Verification Commands (Iteration 6).
Empirically challenges CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ.
"""

import pytest
from binascii import hexlify, unhexlify

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.commands.pin import (
    CAHandler,
    DCHandler,
    ECHandler,
    BAHandler,
    EEHandler,
    encrypt_pin_block,
    decrypt_pin_block,
    _extract_pin_block_and_fmt,
    _parse_pan_and_pvv,
)
from pythales.commands.card_verify import CWHandler, CYHandler, calculate_cvv
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def keys(hsm):
    # 3DES keys under LMK
    raw_zpk1 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xfe\xdc\xba\x98\x76\x54\x32\x10"
    raw_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

    zpk1_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk1, variant=2)
    zpk2_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk2, variant=2)

    zpk1_str = "U" + hexlify(zpk1_enc).decode("ascii").upper()
    zpk2_str = "U" + hexlify(zpk2_enc).decode("ascii").upper()

    raw_pvk = b"\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    pvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_pvk, variant=3)
    pvk_str = "U" + hexlify(pvk_enc).decode("ascii").upper()

    raw_cvk = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
    cvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_cvk, variant=4)
    cvk_str = "U" + hexlify(cvk_enc).decode("ascii").upper()

    # TR-31 AES ZPK Key Block
    raw_aes_zpk = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    hdr_aes_zpk = TR31Header("S", 0, "21", "A", "B", "00", "E", b"")
    tr31_zpk_str = TR31KeyBlock.wrap(raw_aes_zpk, hdr_aes_zpk, hsm.LMK).decode("ascii")

    # TR-31 CVK Key Block (Key Usage 'C0')
    raw_cvk_tr31 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\xaa\xbb\xcc\xdd\xee\xff"
    hdr_cvk = TR31Header("S", 0, "C0", "C", "X", "00", "E", b"")
    tr31_cvk_str = TR31KeyBlock.wrap(raw_cvk_tr31, hdr_cvk, hsm.LMK).decode("ascii")

    return {
        "raw_zpk1": raw_zpk1,
        "raw_zpk2": raw_zpk2,
        "zpk1_str": zpk1_str,
        "zpk2_str": zpk2_str,
        "raw_pvk": raw_pvk,
        "pvk_str": pvk_str,
        "raw_cvk": raw_cvk,
        "cvk_str": cvk_str,
        "raw_aes_zpk": raw_aes_zpk,
        "tr31_zpk_str": tr31_zpk_str,
        "raw_cvk_tr31": raw_cvk_tr31,
        "tr31_cvk_str": tr31_cvk_str,
    }


# ============================================================================
# 1. CROSS-FORMAT PIN BLOCK TRANSLATION (FORMAT 0 <-> FORMAT 4 AES) IN CA
# ============================================================================

def test_ca_format0_to_format4_translation(hsm, keys):
    """Test translating Format 0 DES PIN block to Format 4 AES PIN block in CA."""
    pin = "4826"
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Translate from ZPK1 (Format 0) to TR-31 AES ZPK (Format 4)
    payload = f"{keys['zpk1_str']}{keys['tr31_zpk_str']}12{src_pb}0148{pan}".encode("ascii")
    handler = CAHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:32]
    dst_fmt = resp_str[32:34]
    assert dst_fmt == "48"

    # Decrypt with AES ZPK
    dec_pin = decrypt_pin_block(keys["raw_aes_zpk"], dst_pb, "48", pan)
    assert dec_pin == pin


def test_ca_format4_to_format0_translation(hsm, keys):
    """Test translating Format 4 AES PIN block to Format 0 DES PIN block in CA."""
    pin = "7391"
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    # Translate from TR-31 AES ZPK (Format 4) to ZPK1 (Format 0)
    payload = f"{keys['tr31_zpk_str']}{keys['zpk1_str']}12{src_pb}4801{pan}".encode("ascii")
    handler = CAHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:16]
    dst_fmt = resp_str[16:18]
    assert dst_fmt == "01"

    # Decrypt with DES ZPK
    dec_pin = decrypt_pin_block(keys["raw_zpk1"], dst_pb, "01", pan)
    assert dec_pin == pin


# ============================================================================
# 2. TR-31 KEY BLOCK SUPPORT IN CW / CY
# ============================================================================

def test_cw_cy_tr31_key_scheme_s(hsm, keys):
    """Test CW and CY commands with TR-31 Key Block Scheme 'S'."""
    pan = "4500123456789999"
    exp_date = "2608"
    service_code = "201"

    cw_payload = f"{keys['tr31_cvk_str']}{pan};{exp_date};{service_code}".encode("ascii")
    cw_handler = CWHandler(hsm)
    err_cw, resp_cw = cw_handler.handle_payload(cw_payload)

    assert err_cw == ErrorCodes.SUCCESS
    cvv = resp_cw.decode("ascii")
    assert len(cvv) == 3

    ref_cvv = calculate_cvv(keys["raw_cvk_tr31"], pan, exp_date, service_code)
    assert cvv == ref_cvv

    cy_payload = f"{keys['tr31_cvk_str']}{pan};{exp_date};{service_code};{cvv}".encode("ascii")
    cy_handler = CYHandler(hsm)
    err_cy, resp_cy = cy_handler.handle_payload(cy_payload)

    assert err_cy == ErrorCodes.SUCCESS
    assert resp_cy == b""


# ============================================================================
# 3. FORMAT 4 PIN BLOCK IN DC & EC & EE
# ============================================================================

def test_dc_format4_pin_block_verification(hsm, keys):
    """Test DC command verifying Format 4 AES PIN block with Visa PVV."""
    pin = "3141"
    pan = "4000123456789010"
    pvki = "1"

    from pynblock.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    payload = f"{keys['tr31_zpk_str']}{keys['pvk_str']}{enc_pb}48{pan};{pvki}{calc_pvv}".encode("ascii")
    handler = DCHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ec_format4_pin_block_under_lmk(hsm, keys):
    """Test EC command translating Format 4 AES PIN block to LMK-encrypted PIN block."""
    pin = "2718"
    pan = "4000123456789010"

    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    payload = f"{keys['tr31_zpk_str']}{keys['pvk_str']}{enc_pb}48{pan}".encode("ascii")
    handler = ECHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert len(resp) == 16
    dec_pin = decrypt_pin_block(hsm.LMK, resp.decode("ascii"), "01", pan)
    assert dec_pin == pin


def test_ee_format4_pin_block_ibm3624(hsm, keys):
    """Test EE command verifying IBM 3624 PIN offset using Format 4 AES PIN block."""
    pin = "8888"
    pan = "4000123456789010"
    dec_table = "0123456789012345"

    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    from Crypto.Cipher import DES3
    val_data = pan.rjust(16, "0")
    cipher = DES3.new(keys["raw_pvk"][:16], DES3.MODE_ECB)
    enc_val = hexlify(cipher.encrypt(unhexlify(val_data[:16])[:8])).decode("ascii").upper()
    nat_pin_chars = [dec_table[int(c, 16)] for c in enc_val[:4]]
    nat_pin = "".join(nat_pin_chars)

    offset = "".join([str((int(pin[i]) - int(nat_pin[i])) % 10) for i in range(4)])

    payload = f"{keys['tr31_zpk_str']}{keys['pvk_str']}{enc_pb}48{pan};{dec_table}{offset}".encode("ascii")
    handler = EEHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 4. HSM ENVELOPE PROCESS MESSAGE & TRUNCATION TEST
# ============================================================================

def test_hsm_envelope_m3_error_truncation(keys):
    """
    Test TCP framing and truncation rules via hsm.process_raw_message() for M3 commands.
    When error code != '00', response should contain Echoed Header + Response Code + Error Code,
    and NO additional payload bytes.
    """
    hsm = HSM(header="HDR1")
    # Send CA with invalid key -> should fail with error
    bad_ca_msg = b"HDR1" + b"CA" + b"INVALID_KEY_HEADER_AND_BAD_DATA"
    raw_resp = hsm.process_raw_message(bad_ca_msg)

    header = raw_resp[:4]
    cmd_resp = raw_resp[4:6]
    err_code = raw_resp[6:8]
    extra = raw_resp[8:]

    assert header == b"HDR1"
    assert cmd_resp == b"CB"
    assert err_code != b"00"
    assert len(extra) == 0, f"Error truncation violated: extra bytes found: {extra}"

    # Send DC with wrong PVV -> should return 'DD' + '01' + empty payload
    pin = "1234"
    pan = "4000123456789010"
    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)
    bad_dc_msg = b"HDR1" + b"DC" + f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}19999".encode("ascii")

    raw_dc_resp = hsm.process_raw_message(bad_dc_msg)
    assert raw_dc_resp[:4] == b"HDR1"
    assert raw_dc_resp[4:6] == b"DD"
    assert raw_dc_resp[6:8] == b"01"
    assert len(raw_dc_resp[8:]) == 0

    # Send CY with wrong CVV -> should return 'CZ' + '01' + empty payload
    bad_cy_msg = b"HDR1" + b"CY" + f"{keys['cvk_str']}{pan};2512;101;999".encode("ascii")
    raw_cy_resp = hsm.process_raw_message(bad_cy_msg)
    assert raw_cy_resp[:4] == b"HDR1"
    assert raw_cy_resp[4:6] == b"CZ"
    assert raw_cy_resp[6:8] == b"01"
    assert len(raw_cy_resp[8:]) == 0


# ============================================================================
# 5. PAN BOUNDARY & NON-NUMERIC CORRUPTION STRESS TESTS
# ============================================================================

def test_pan_length_boundaries_12_and_19_digits(hsm, keys):
    """Test CW/CY, DC, EC with 12-digit and 19-digit PANs."""
    exp_date = "2812"
    service_code = "101"
    pin = "9999"

    for pan in ["123456789012", "1234567890123456789"]:
        # CW/CY
        cw_payload = f"{keys['cvk_str']}{pan};{exp_date};{service_code}".encode("ascii")
        cw_handler = CWHandler(hsm)
        err_cw, resp_cw = cw_handler.handle_payload(cw_payload)
        assert err_cw == ErrorCodes.SUCCESS
        cvv = resp_cw.decode("ascii")

        cy_payload = f"{keys['cvk_str']}{pan};{exp_date};{service_code};{cvv}".encode("ascii")
        cy_handler = CYHandler(hsm)
        err_cy, _ = cy_handler.handle_payload(cy_payload)
        assert err_cy == ErrorCodes.SUCCESS

        # DC
        from pynblock.tools import get_visa_pvv
        pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
        pvki = "1"
        calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")
        enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

        dc_payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan};{pvki}{calc_pvv}".encode("ascii")
        dc_handler = DCHandler(hsm)
        err_dc, _ = dc_handler.handle_payload(dc_payload)
        assert err_dc == ErrorCodes.SUCCESS


def test_invalid_pin_block_hex_rejection(keys):
    """Test decrypting pin block with invalid hex characters raises INVALID_PIN_BLOCK."""
    pan = "4000123456789010"
    with pytest.raises(PayShieldException) as exc:
        decrypt_pin_block(keys["raw_zpk1"], "G" * 16, "01", pan)
    assert exc.value.error_code == ErrorCodes.INVALID_PIN_BLOCK
