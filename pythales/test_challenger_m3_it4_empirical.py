"""
Empirical Stress Test Harness for PyThales M3 PIN & Card Verification Commands (Iteration 4).
Tests CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ.
"""

import pytest
import os
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
    """Returns a fresh HSM instance initialized with standard LMK."""
    return HSM()


@pytest.fixture
def keys(hsm):
    """Generates sample keys encrypted under LMK for testing."""
    # Variant 2 ZPK / TPK keys (3DES & AES)
    raw_zpk1 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xfe\xdc\xba\x98\x76\x54\x32\x10"
    raw_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

    zpk1_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk1, variant=2)
    zpk2_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk2, variant=2)

    zpk1_str = "U" + hexlify(zpk1_enc).decode("ascii").upper()
    zpk2_str = "U" + hexlify(zpk2_enc).decode("ascii").upper()

    # Variant 3 PVK key (3DES)
    raw_pvk = b"\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    pvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_pvk, variant=3)
    pvk_str = "U" + hexlify(pvk_enc).decode("ascii").upper()

    # Variant 4 CVK key (3DES)
    raw_cvk = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
    cvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_cvk, variant=4)
    cvk_str = "U" + hexlify(cvk_enc).decode("ascii").upper()

    # TR-31 AES Key Block (Key Usage '21' ZPK, Alg 'A')
    raw_aes_zpk = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    hdr_aes = TR31Header("S", 0, "21", "A", "B", "00", "E", b"")
    tr31_zpk_bytes = TR31KeyBlock.wrap(raw_aes_zpk, hdr_aes, hsm.LMK)
    tr31_zpk_str = tr31_zpk_bytes.decode("ascii")

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
    }


# ============================================================================
# 1. PIN BLOCK FORMAT 0 & FORMAT 4 (AES) PRIMITIVE TESTS
# ============================================================================

def test_pin_block_format0_roundtrip(keys):
    """Test encrypt and decrypt of ISO 9564-1 Format 0 PIN block."""
    pin = "1234"
    pan = "4000123456789010"
    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)
    assert len(enc_pb) == 16
    dec_pin = decrypt_pin_block(keys["raw_zpk1"], enc_pb, "01", pan)
    assert dec_pin == pin


def test_pin_block_format4_aes_roundtrip(keys):
    """Test encrypt and decrypt of ISO 9564-1 Format 4 (AES) PIN block."""
    pin = "123456"
    pan = "4000123456789010"
    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)
    assert len(enc_pb) == 32
    dec_pin = decrypt_pin_block(keys["raw_aes_zpk"], enc_pb, "48", pan)
    assert dec_pin == pin


def test_pin_block_format4_pan_length_variations(keys):
    """Test Format 4 PIN block with various PAN lengths (12, 13, 16, 19)."""
    pin = "9876"
    for pan in ["123456789012", "1234567890123", "4000123456789010", "1234567890123456789"]:
        enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)
        assert len(enc_pb) == 32
        dec_pin = decrypt_pin_block(keys["raw_aes_zpk"], enc_pb, "48", pan)
        assert dec_pin == pin


def test_pin_block_format4_pan_short(keys):
    """Test Format 4 PIN block with PAN < 12 digits (padded to 12)."""
    pin = "4321"
    pan = "1234567890"  # 10 digits
    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "04", pan)
    assert len(enc_pb) == 32
    dec_pin = decrypt_pin_block(keys["raw_aes_zpk"], enc_pb, "04", pan)
    assert dec_pin == pin


def test_pin_block_invalid_lengths(keys):
    """Test invalid PIN lengths (<4 or >12)."""
    pan = "4000123456789010"
    with pytest.raises(PayShieldException) as exc1:
        encrypt_pin_block(keys["raw_zpk1"], "123", "01", pan)
    assert exc1.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE

    with pytest.raises(PayShieldException) as exc2:
        encrypt_pin_block(keys["raw_zpk1"], "1234567890123", "01", pan)
    assert exc2.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


# ============================================================================
# 2. CA COMMAND (TRANSLATE PIN BLOCK) TESTS
# ============================================================================

def test_ca_format0_to_format0(hsm, keys):
    """Test CA command translating Format 0 PIN block from ZPK1 to ZPK2."""
    pin = "5678"
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Payload: ZPK1 (33 chars) + ZPK2 (33 chars) + max_pin_len "12" + src_pb "..." + src_fmt "01" + dst_fmt "01" + PAN
    payload = f"{keys['zpk1_str']}{keys['zpk2_str']}12{src_pb}0101{pan}".encode("ascii")
    handler = CAHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:16]
    dst_fmt = resp_str[16:18]
    assert dst_fmt == "01"

    dec_pin = decrypt_pin_block(keys["raw_zpk2"], dst_pb, dst_fmt, pan)
    assert dec_pin == pin


def test_ca_format4_to_format4(hsm, keys):
    """Test CA command translating Format 4 (AES) PIN block from ZPK1 to ZPK2 using TR-31 keys."""
    pin = "123456"
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    # TR-31 key block length is variable, let's wrap a second TR-31 ZPK key
    raw_aes_zpk2 = b"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef"
    hdr_aes = TR31Header("S", 0, "21", "A", "B", "00", "E", b"")
    tr31_zpk2_str = TR31KeyBlock.wrap(raw_aes_zpk2, hdr_aes, hsm.LMK).decode("ascii")

    payload = f"{keys['tr31_zpk_str']}{tr31_zpk2_str}12{src_pb}4848{pan}".encode("ascii")
    handler = CAHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:32]
    dst_fmt = resp_str[32:34]
    assert dst_fmt == "48"

    dec_pin = decrypt_pin_block(raw_aes_zpk2, dst_pb, dst_fmt, pan)
    assert dec_pin == pin


def test_ca_max_pin_length_exceeded(hsm, keys):
    """Test CA command rejecting PIN exceeding max PIN length field."""
    pin = "123456"  # 6 digits
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Set max PIN length to "04"
    payload = f"{keys['zpk1_str']}{keys['zpk2_str']}04{src_pb}0101{pan}".encode("ascii")
    handler = CAHandler(hsm)
    with pytest.raises(PayShieldException) as exc:
        handler.handle_payload(payload)
    assert exc.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


def test_ca_payload_too_short(hsm):
    """Test CA payload shorter than 30 characters raises INVALID_DATA_LENGTH (15)."""
    handler = CAHandler(hsm)
    with pytest.raises(PayShieldException) as exc:
        handler.handle_payload(b"U123456789")
    assert exc.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 3. DC COMMAND (VERIFY CUSTOMER PIN) TESTS
# ============================================================================

def test_dc_verify_visa_pvv_success(hsm, keys):
    """Test DC command verifying valid Visa PVV."""
    pin = "1234"
    pan = "4000123456789010"
    pvki = "1"
    
    # Calculate valid VISA PVV using pynblock get_visa_pvv
    from pynblock.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # TPK + PVK + PIN_BLOCK + FMT + PAN + PVKI + PVV
    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    handler = DCHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_dc_verify_visa_pvv_mismatch(hsm, keys):
    """Test DC command returning error '01' on PVV mismatch."""
    pin = "1234"
    pan = "4000123456789010"
    pvki = "1"
    wrong_pvv = "9999"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}{pvki}{wrong_pvv}".encode("ascii")
    handler = DCHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.LMK_ERROR  # '01' mismatch


def test_dc_semicolon_delimited_pan(hsm, keys):
    """Test DC command with semicolon-delimited PAN payload."""
    pin = "4321"
    pan = "4000123456789010"
    pvki = "1"

    from pynblock.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Payload with semicolon before PVKI/PVV: PAN;PVKI PVV
    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan};{pvki}{calc_pvv}".encode("ascii")
    handler = DCHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS


# ============================================================================
# 4. EC COMMAND (TRANSLATE PIN UNDER LMK / VERIFY INTERCHANGE PIN) TESTS
# ============================================================================

def test_ec_with_pvv_verification_success(hsm, keys):
    """Test EC command with PVV verification success."""
    pin = "9876"
    pan = "4000123456789010"
    pvki = "1"

    from pynblock.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    handler = ECHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ec_without_pvv_translates_under_lmk(hsm, keys):
    """Test EC command without PVV returns PIN block encrypted under LMK."""
    pin = "5432"
    pan = "4000123456789010"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Payload without PVV (PAN only)
    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}".encode("ascii")
    handler = ECHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert len(resp) == 16  # PIN block under LMK

    # Verify decrypted PIN under LMK matches original pin
    dec_pin_lmk = decrypt_pin_block(hsm.LMK, resp.decode("ascii"), "01", pan)
    assert dec_pin_lmk == pin


# ============================================================================
# 5. BA COMMAND (GENERATE / ENCRYPT CLEAR PIN) TESTS
# ============================================================================

def test_ba_generate_random_pin(hsm):
    """Test BA command generating random clear PIN."""
    handler = BAHandler(hsm)
    
    # Empty payload -> random 4-digit PIN
    err1, resp1 = handler.handle_payload(b"")
    assert err1 == ErrorCodes.SUCCESS
    assert len(resp1) == 4
    assert resp1.decode("ascii").isdigit()

    # Requested length "06" -> random 6-digit PIN
    err2, resp2 = handler.handle_payload(b"06")
    assert err2 == ErrorCodes.SUCCESS
    assert len(resp2) == 6
    assert resp2.decode("ascii").isdigit()


def test_ba_encrypt_clear_pin_under_zpk(hsm, keys):
    """Test BA command encrypting clear PIN under ZPK."""
    pin = "6543"
    pan = "4000123456789010"

    # Payload: ZPK + PAN + ";" + clear_pin
    payload = f"{keys['zpk1_str']}{pan};{pin}".encode("ascii")
    handler = BAHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    # Response contains clear PIN (4 digits) + encrypted PIN block (16 hex chars)
    out_clear_pin = resp_str[:4]
    out_enc_pb = resp_str[4:]

    assert out_clear_pin == pin
    assert len(out_enc_pb) == 16

    # Verify encrypted PIN block decrypts properly
    dec_pin = decrypt_pin_block(keys["raw_zpk1"], out_enc_pb, "01", pan)
    assert dec_pin == pin


# ============================================================================
# 6. EE COMMAND (VERIFY IBM 3624 PIN OFFSET) TESTS
# ============================================================================

def test_ee_verify_ibm3624_offset_success(hsm, keys):
    """Test EE command verifying valid IBM 3624 PIN offset."""
    pin = "1234"
    pan = "4000123456789010"
    dec_table = "0123456789012345"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Compute expected natural PIN for validation data
    from Crypto.Cipher import DES3
    val_data = pan.rjust(16, "0")
    cipher = DES3.new(keys["raw_pvk"][:16], DES3.MODE_ECB)
    enc_val = hexlify(cipher.encrypt(unhexlify(val_data[:16])[:8])).decode("ascii").upper()
    nat_pin_chars = [dec_table[int(c, 16)] for c in enc_val[:4]]
    nat_pin = "".join(nat_pin_chars)

    # offset = (pin_digit - nat_digit) mod 10
    offset = "".join([str((int(pin[i]) - int(nat_pin[i])) % 10) for i in range(4)])

    # Payload: ZPK + PVK + PIN_BLOCK + FMT + PAN + ";" + DEC_TABLE + OFFSET
    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan};{dec_table}{offset}".encode("ascii")
    handler = EEHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ee_verify_ibm3624_offset_mismatch(hsm, keys):
    """Test EE command returning error '01' on wrong offset."""
    pin = "1234"
    pan = "4000123456789010"
    dec_table = "0123456789012345"
    wrong_offset = "9999"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan};{dec_table}{wrong_offset}".encode("ascii")
    handler = EEHandler(hsm)
    err, resp = handler.handle_payload(payload)

    assert err == ErrorCodes.LMK_ERROR


# ============================================================================
# 7. CW & CY COMMANDS (GENERATE & VERIFY CVV) TESTS
# ============================================================================

def test_cw_and_cy_cvv_workflow(hsm, keys):
    """Test CW generate CVV and CY verify CVV workflow."""
    pan = "4000123456789010"
    exp_date = "2512"
    service_code = "101"

    # CW Generate CVV with semicolon delimited payload: CVK + PAN;YYMM;SVC
    cw_payload = f"{keys['cvk_str']}{pan};{exp_date};{service_code}".encode("ascii")
    cw_handler = CWHandler(hsm)
    err_cw, resp_cw = cw_handler.handle_payload(cw_payload)

    assert err_cw == ErrorCodes.SUCCESS
    cvv = resp_cw.decode("ascii")
    assert len(cvv) == 3
    assert cvv.isdigit()

    # Direct calculation comparison
    calc_cvv_ref = calculate_cvv(keys["raw_cvk"], pan, exp_date, service_code)
    assert cvv == calc_cvv_ref

    # CY Verify CVV with semicolon delimited payload: CVK + PAN;YYMM;SVC;CVV
    cy_payload = f"{keys['cvk_str']}{pan};{exp_date};{service_code};{cvv}".encode("ascii")
    cy_handler = CYHandler(hsm)
    err_cy, resp_cy = cy_handler.handle_payload(cy_payload)

    assert err_cy == ErrorCodes.SUCCESS
    assert resp_cy == b""

    # CY Verify CVV with wrong CVV
    cy_wrong_payload = f"{keys['cvk_str']}{pan};{exp_date};{service_code};999".encode("ascii")
    err_cy_wrong, _ = cy_handler.handle_payload(cy_wrong_payload)
    assert err_cy_wrong == ErrorCodes.LMK_ERROR


def test_cw_non_delimited_format(hsm, keys):
    """Test CW generate CVV with packed non-delimited PAN+YYMM+SVC."""
    pan = "4000123456789010"  # 16 digits
    exp_date = "2512"         # 4 digits
    service_code = "101"      # 3 digits
    # Total = 23 digits

    cw_payload = f"{keys['cvk_str']}{pan}{exp_date}{service_code}".encode("ascii")
    cw_handler = CWHandler(hsm)
    err_cw, resp_cw = cw_handler.handle_payload(cw_payload)

    assert err_cw == ErrorCodes.SUCCESS
    cvv = resp_cw.decode("ascii")
    assert len(cvv) == 3


def test_cw_and_cy_payload_too_short(hsm):
    """Test CW and CY short payloads raise INVALID_DATA_LENGTH."""
    cw_handler = CWHandler(hsm)
    with pytest.raises(PayShieldException) as exc1:
        cw_handler.handle_payload(b"U12345678")
    assert exc1.value.error_code == ErrorCodes.INVALID_DATA_LENGTH

    cy_handler = CYHandler(hsm)
    with pytest.raises(PayShieldException) as exc2:
        cy_handler.handle_payload(b"U12345678")
    assert exc2.value.error_code == ErrorCodes.INVALID_DATA_LENGTH
