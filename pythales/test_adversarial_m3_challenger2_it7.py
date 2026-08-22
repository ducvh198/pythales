"""
Adversarial Test Suite - Milestone M3 (PIN & Card Verification Commands)
Challenger 2 - Iteration 7
"""

import pytest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
from pythales.crypto.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock
from pythales.commands.pin import (
    encrypt_pin_block,
    decrypt_pin_block,
    CAHandler,
    DCHandler,
    ECHandler,
    BAHandler,
    EEHandler,
)
from pythales.commands.card_verify import (
    calculate_cvv,
    CWHandler,
    CYHandler,
)


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
# 1. CA Command TR-31 & Cross-Scheme PIN Block Translation Tests
# ============================================================================

def test_ca_tr31_zpk_to_tr31_zpk_translation(hsm, keys):
    """Test CA translating PIN block between two TR-31 wrapped ZPKs."""
    pan = "4575271111567890"
    pin = "9876"
    src_pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    
    # Create second TR-31 ZPK
    tr31_zpk2 = TR31KeyBlock.wrap(keys["clear_zpk2"], "S0048P0TD00E0000", hsm.LMK).decode("ascii")

    payload = (keys["tr31_zpk"] + tr31_zpk2 + "12" + src_pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pin_block = resp_str[:16]
    dst_fmt = resp_str[16:]
    assert dst_fmt == "01"
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], dst_pin_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_scheme_t_3des_key_translation(hsm, keys):
    """Test CA translating PIN block using 24-byte 3DES key (Scheme T)."""
    pan = "4575271111567890"
    pin = "4321"
    src_pin_block = encrypt_pin_block(keys["clear_zpk3"], pin, "01", pan)

    payload = (keys["zpk3_t"] + keys["zpk_u"] + "12" + src_pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pin_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], dst_pin_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_exact_max_pin_len_boundary(hsm, keys):
    """Test CA passing when clear PIN length matches max_pin_len boundary exactly."""
    pan = "4575271111567890"
    pin = "12345"  # len 5
    src_pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    
    # max_pin_len = "05" (matches len 5 exactly)
    payload = (keys["zpk_u"] + keys["zpk2_x"] + "05" + src_pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pin_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], dst_pin_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_short_payload_raises_invalid_data_length(hsm):
    """Test CA raising INVALID_DATA_LENGTH ('15') when payload is too short."""
    payload = b"U12345678901234567890"
    with pytest.raises(PayShieldException) as exc_info:
        CAHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 2. DC Command TR-31 Keys & Edge Case Tests
# ============================================================================

def test_dc_tr31_tpk_and_tr31_pvk_verification(hsm, keys):
    """Test DC verification using TR-31 wrapped TPK and PVK keys."""
    pan = "4575272222567890"
    pin = "2468"
    pvki = "1"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["tr31_zpk"] + keys["tr31_pvk"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")

    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_dc_19digit_pan_pvv_verification(hsm, keys):
    """Test DC verifying PVV with a 19-digit PAN."""
    pan = "4575272222567890123"
    pin = "1357"
    pvki = "3"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")

    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_dc_short_payload_raises_invalid_data_length(hsm):
    """Test DC raising INVALID_DATA_LENGTH ('15') when payload is too short."""
    payload = b"U12345678901234567890"
    with pytest.raises(PayShieldException) as exc_info:
        DCHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 3. EC Command TR-31 & Format 4 (AES) PIN Block Tests
# ============================================================================

def test_ec_tr31_keys_verification_success(hsm, keys):
    """Test EC interchange PIN verification with TR-31 wrapped ZPK and PVK keys."""
    pan = "4575272222567890"
    pin = "1122"
    pvki = "1"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["tr31_zpk"] + keys["tr31_pvk"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")

    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ec_format4_aes_pin_translation_under_lmk(hsm, keys):
    """Test EC translating Format 4 (AES) PIN block under LMK when no PVV is supplied."""
    pan = "4575272222567890"
    pin = "8765"
    pin_block = encrypt_pin_block(keys["clear_aes_zpk"], pin, "48", pan)
    payload = (keys["aes_zpk_u"] + keys["pvk_u"] + pin_block + "48" + pan).encode("ascii")

    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    pin_under_lmk = resp.decode("ascii")
    assert len(pin_under_lmk) == 16

    decrypted_pin = decrypt_pin_block(hsm.LMK, pin_under_lmk, "01", pan)
    assert decrypted_pin == pin


def test_ec_short_payload_raises_invalid_data_length(hsm):
    """Test EC raising INVALID_DATA_LENGTH ('15') when payload is too short."""
    payload = b"U12345678901234567890"
    with pytest.raises(PayShieldException) as exc_info:
        ECHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 4. BA Command Encrypt Clear PIN & Parameterized Edge Cases
# ============================================================================

def test_ba_encrypt_clear_pin_with_tr31_zpk(hsm, keys):
    """Test BA encrypting clear PIN using TR-31 ZPK."""
    pan = "4575272222567890"
    clear_pin = "5678"
    payload = (keys["tr31_zpk"] + pan + ";" + clear_pin).encode("ascii")

    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_clear_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    assert out_clear_pin == clear_pin
    assert len(enc_pin_block) == 16

    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == clear_pin


def test_ba_clear_pin_with_f_delimiter(hsm, keys):
    """Test BA parsing clear PIN when 'F' delimiter is used."""
    pan = "4575272222567890"
    clear_pin = "9988"
    payload = (keys["zpk_u"] + pan + "F" + clear_pin).encode("ascii")

    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    assert resp_str[:4] == clear_pin
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], resp_str[4:], "01", pan)
    assert decrypted_pin == clear_pin


def test_ba_non_numeric_clear_pin_raises_error(hsm, keys):
    """Test BA raising PIN_LENGTH_OUT_OF_RANGE when clear PIN contains non-digits."""
    pan = "4575272222567890"
    invalid_pin = "12AB"
    payload = (keys["zpk_u"] + pan + ";" + invalid_pin).encode("ascii")

    with pytest.raises(PayShieldException) as exc_info:
        BAHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


# ============================================================================
# 5. EE Command IBM 3624 Offset Verification TR-31 & Edge Cases
# ============================================================================

def test_ee_tr31_keys_verification_success(hsm, keys):
    """Test EE IBM 3624 PIN offset verification with TR-31 ZPK and PVK keys."""
    pan = "4575272222567890"
    dec_table = "0123456789012345"
    validation_data = "4575272222567890"
    pvk_bytes = keys["clear_pvk"]

    val_bytes = unhexlify(validation_data[:16])
    cipher = Crypto.Cipher.DES3.new(pvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)
    enc_val_hex = hexlify(cipher.encrypt(val_bytes[:8])).decode("ascii").upper()

    nat_pin_chars = [dec_table[int(c, 16)] for c in enc_val_hex[:4]]
    nat_pin = "".join(nat_pin_chars)

    customer_pin = "7654"
    offset_chars = []
    for i in range(4):
        diff = (int(customer_pin[i]) - int(nat_pin[i])) % 10
        offset_chars.append(str(diff))
    offset = "".join(offset_chars)

    pin_block = encrypt_pin_block(keys["clear_zpk"], customer_pin, "01", pan)
    payload = (keys["tr31_zpk"] + keys["tr31_pvk"] + pin_block + "01" + pan + ";" + dec_table + offset + validation_data).encode("ascii")

    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ee_incomplete_decimalization_table_raises_error(hsm, keys):
    """Test EE raising INVALID_DATA_LENGTH ('15') when decimalization table is < 16 chars."""
    pan = "4575272222567890"
    pin_block = encrypt_pin_block(keys["clear_zpk"], "1234", "01", pan)
    short_dec_table = "01234567"  # only 8 chars
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";" + short_dec_table).encode("ascii")

    with pytest.raises(PayShieldException) as exc_info:
        EEHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 6. CW & CY Command TR-31 & Track 2 Delimiter Tests
# ============================================================================

def test_cw_tr31_cvk_generation(hsm, keys):
    """Test CW CVV generation using TR-31 CVK key."""
    pan = "4575272222567890"
    exp = "2708"
    svc = "999"

    payload = (keys["tr31_cvk"] + f"{pan};{exp};{svc}").encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    cvv = resp.decode("ascii")
    assert len(cvv) == 3 and cvv.isdigit()


def test_cy_tr31_cvk_verification(hsm, keys):
    """Test CY CVV verification using TR-31 CVK key."""
    pan = "4575272222567890"
    exp = "2708"
    svc = "999"

    cw_payload = (keys["tr31_cvk"] + f"{pan};{exp};{svc}").encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(cw_payload)
    cvv = resp.decode("ascii")

    cy_payload = (keys["tr31_cvk"] + f"{pan};{exp};{svc};{cvv}").encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(cy_payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_cy_track2_layout_with_equals(hsm, keys):
    """Test CY with Track 2 layout containing '=' delimiter."""
    pan = "4575272222567890"
    exp = "2612"
    svc = "101"

    cw_payload = (keys["cvk_u"] + f"{pan};{exp};{svc}").encode("ascii")
    _, resp = CWHandler(hsm).handle_payload(cw_payload)
    cvv = resp.decode("ascii")

    # Layout: CVV;PAN=YYMMSVC...
    cy_payload = (keys["cvk_u"] + f"{cvv};{pan}={exp}{svc}").encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(cy_payload)

    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 7. Raw Envelope Error Truncation Verification for M3 Error Exceptions
# ============================================================================

def test_hsm_process_raw_message_truncates_payload_on_exception(hsm, keys):
    """Verify raw TCP message processor truncates response on exceptions in M3 commands."""
    header = b"HDR1"
    hsm_with_header = HSM(header="HDR1")

    # Send CA with payload too short -> throws PayShieldException(INVALID_DATA_LENGTH '15')
    raw_req = header + b"CA" + b"TOO_SHORT"
    raw_resp = hsm_with_header.process_raw_message(raw_req)

    # Output MUST be header + CB + 15 and MUST NOT have any response data
    assert raw_resp == header + b"CB" + b"15"
