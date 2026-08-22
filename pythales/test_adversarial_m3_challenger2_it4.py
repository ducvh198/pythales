"""
Adversarial Stress Test Suite - Milestone M3 (PIN & Card Verification Commands)
Challenger 2 - Iteration 4
"""

import pytest
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock
from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block, CAHandler, DCHandler, ECHandler, BAHandler, EEHandler
from pythales.commands.card_verify import calculate_cvv, CWHandler, CYHandler
from pythales.crypto.tools import get_visa_pvv


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def keys(hsm):
    # Setup test keys under LMK
    # ZPK (Variant 2)
    clear_zpk = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xfe\xdc\xba\x98\x76\x54\x32\x10"
    enc_zpk = hsm.lmk_engine.encrypt_under_lmk(clear_zpk, variant=2)
    zpk_str = "U" + hexlify(enc_zpk).decode("ascii").upper()

    # ZPK2 (Variant 2)
    clear_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
    enc_zpk2 = hsm.lmk_engine.encrypt_under_lmk(clear_zpk2, variant=2)
    zpk2_str = "U" + hexlify(enc_zpk2).decode("ascii").upper()

    # PVK (Variant 3)
    clear_pvk = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
    enc_pvk = hsm.lmk_engine.encrypt_under_lmk(clear_pvk, variant=3)
    pvk_str = "U" + hexlify(enc_pvk).decode("ascii").upper()

    # CVK (Variant 4)
    clear_cvk = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x11\x22\x33\x44\x55\x66\x77\x88"
    enc_cvk = hsm.lmk_engine.encrypt_under_lmk(clear_cvk, variant=4)
    cvk_str = "U" + hexlify(enc_cvk).decode("ascii").upper()

    # AES ZPK (128-bit) for Format 4
    clear_aes_zpk = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    enc_aes_zpk = hsm.lmk_engine.encrypt_under_lmk(clear_aes_zpk, variant=2)
    aes_zpk_str = "U" + hexlify(enc_aes_zpk).decode("ascii").upper()

    # TR-31 ZPK Key Block (Scheme S)
    tr31_zpk_str = TR31KeyBlock.wrap(clear_zpk, "S0048P0TD00E0000", hsm.LMK).decode("ascii")

    return {
        "clear_zpk": clear_zpk,
        "zpk_str": zpk_str,
        "clear_zpk2": clear_zpk2,
        "zpk2_str": zpk2_str,
        "clear_pvk": clear_pvk,
        "pvk_str": pvk_str,
        "clear_cvk": clear_cvk,
        "cvk_str": cvk_str,
        "clear_aes_zpk": clear_aes_zpk,
        "aes_zpk_str": aes_zpk_str,
        "tr31_zpk_str": tr31_zpk_str,
    }


# ============================================================================
# Edge Case 1: CA/CB Omitted dst_fmt with 16-digit PANs (40, 45, 51, 37, 48)
# ============================================================================

def test_ca_cb_omitted_dst_fmt_pan_40(hsm, keys):
    """CA command with omitted dst_fmt and 16-digit PAN starting with '40'."""
    pan = "4012345678901234"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    # Payload: src_zpk + dst_zpk + max_pin_len("12") + pin_block + src_fmt("01") + pan
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    out_fmt = resp_str[16:]
    assert out_fmt == "01"
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_cb_omitted_dst_fmt_pan_45(hsm, keys):
    """CA command with omitted dst_fmt and 16-digit PAN starting with '45'."""
    pan = "4575272222567122"
    pin = "4321"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_cb_omitted_dst_fmt_pan_51(hsm, keys):
    """CA command with omitted dst_fmt and 16-digit PAN starting with '51' (Mastercard)."""
    pan = "5105105105105105"
    pin = "9876"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_cb_omitted_dst_fmt_pan_37(hsm, keys):
    """CA command with omitted dst_fmt and 15-digit PAN starting with '37' (Amex)."""
    pan = "378282246310005"
    pin = "1122"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin


def test_ca_cb_omitted_dst_fmt_pan_48(hsm, keys):
    """CA command with omitted dst_fmt and 16-digit PAN starting with '48' (Visa BIN 48xxxx)."""
    pan = "4800123456789012"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "12" + pin_block + "01" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:16]
    decrypted_pin = decrypt_pin_block(keys["clear_zpk2"], out_block, "01", pan)
    assert decrypted_pin == pin



def test_ca_cb_explicit_dst_fmt_48(hsm, keys):
    """CA command translating Format 01 -> Format 48 (ISO Format 4 AES)."""
    pan = "4575272222567122"
    pin = "5566"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    # Payload: src_zpk + dst_zpk + max_len("12") + pin_block + src_fmt("01") + dst_fmt("48") + pan
    payload = (keys["zpk_str"] + keys["aes_zpk_str"] + "12" + pin_block + "01" + "48" + pan).encode("ascii")
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_block = resp_str[:32]
    out_fmt = resp_str[32:]
    assert out_fmt == "48"
    decrypted_pin = decrypt_pin_block(keys["clear_aes_zpk"], out_block, "48", pan)
    assert decrypted_pin == pin


def test_ca_cb_max_pin_len_exceeded(hsm, keys):
    """CA command when PIN length exceeds max_pin_len."""
    pan = "4012345678901234"
    pin = "123456"  # len 6
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    # max_pin_len set to "04"
    payload = (keys["zpk_str"] + keys["zpk2_str"] + "04" + pin_block + "01" + pan).encode("ascii")
    with pytest.raises(PayShieldException) as exc_info:
        CAHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


# ============================================================================
# Edge Case 2: BA/BB 16-Digit PAN Handling & Clear PIN Parsing
# ============================================================================

def test_ba_bb_16_digit_pan_clear_pin(hsm, keys):
    """BA command with 16-digit PAN and clear PIN."""
    pan = "4575272222567122"
    clear_pin = "1234"
    payload = (keys["zpk_str"] + pan + ";" + clear_pin).encode("ascii")
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    ret_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    assert ret_pin == clear_pin
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == clear_pin


def test_ba_bb_16_digit_pan_delimiter_f(hsm, keys):
    """BA command with 16-digit PAN and clear PIN delimited by 'F'."""
    pan = "4575272222567122"
    clear_pin = "5678"
    payload = (keys["zpk_str"] + pan + "F" + clear_pin).encode("ascii")
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    ret_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    assert ret_pin == clear_pin
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == clear_pin


def test_ba_bb_16_digit_pan_explicit_length(hsm, keys):
    """BA command with 16-digit PAN and explicit PIN length '04'."""
    pan = "4575272222567122"
    payload = (keys["zpk_str"] + pan + "04").encode("ascii")
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    ret_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    assert len(ret_pin) == 4
    assert ret_pin.isdigit()
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == ret_pin


def test_ba_bb_16_digit_pan_no_clear_pin_random_generation(hsm, keys):
    """BA command with 16-digit PAN without clear PIN or length (should generate random PIN, not use PAN digits)."""
    pan = "4575272222567122"
    payload = (keys["zpk_str"] + pan + ";").encode("ascii")
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    ret_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    # Must NOT corrupt 16-digit PAN by using last 4 digits ("7122") as clear PIN
    assert ret_pin != pan[-4:], f"BA handler corrupted 16-digit PAN by stealing last 4 digits '{ret_pin}' as PIN"
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == ret_pin



def test_ba_bb_tr31_keyblock(hsm, keys):
    """BA command using TR-31 Key Block (Scheme S)."""
    pan = "4012345678901234"
    clear_pin = "9988"
    payload = (keys["tr31_zpk_str"] + pan + ";" + clear_pin).encode("ascii")
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    ret_pin = resp_str[:4]
    assert ret_pin == clear_pin
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], resp_str[4:], "01", pan)
    assert decrypted_pin == clear_pin


# ============================================================================
# Edge Case 3: DC/DD Visa PVV 16-Digit PAN Slicing
# ============================================================================

def test_dc_dd_visa_pvv_16_digit_pan_success(hsm, keys):
    """DC command with 16-digit PAN Visa PVV verification success."""
    pan = "4575272222567122"
    pin = "1234"
    pvki = "1"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    # Payload: tpk + pvk + pin_block + src_fmt("01") + pan + ";" + pvki + pvv
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_dc_dd_visa_pvv_16_digit_pan_mismatch(hsm, keys):
    """DC command with wrong PVV returning mismatch error ('01')."""
    pan = "4575272222567122"
    pin = "1234"
    pvki = "1"
    wrong_pvv = "0000"

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + ";" + pvki + wrong_pvv).encode("ascii")
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR  # '01'
    assert resp == b""


def test_dc_dd_visa_pvv_format4_aes(hsm, keys):
    """DC command with Format 4 AES PIN block and Visa PVV verification."""
    pan = "4575272222567122"
    pin = "7890"
    pvki = "2"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_aes_zpk"], pin, "48", pan)
    payload = (keys["aes_zpk_str"] + keys["pvk_str"] + pin_block + "48" + pan + ";" + pvki + pvv).encode("ascii")
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# Edge Case 4: EC/ED Visa PVV 16-Digit PAN Slicing
# ============================================================================

def test_ec_ed_visa_pvv_16_digit_pan_success(hsm, keys):
    """EC command with 16-digit PAN Visa PVV verification success."""
    pan = "4575272222567122"
    pin = "4321"
    pvki = "1"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + ";" + pvki + pvv).encode("ascii")
    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ec_ed_no_pvv_returns_pin_under_lmk(hsm, keys):
    """EC command with no PVV provided returns PIN block encrypted under LMK."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan).encode("ascii")
    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_block = resp.decode("ascii")
    decrypted_pin = decrypt_pin_block(hsm.LMK, resp_block, "01", pan)
    assert decrypted_pin == pin


# ============================================================================
# Edge Case 5: CW/CX Semicolon Delimiter Parsing
# ============================================================================

def test_cw_cx_multiple_semicolons(hsm, keys):
    """CW command with multi-semicolon payload (PAN;EXP;SVC)."""
    pan = "4575272222567122"
    exp = "2512"
    svc = "999"
    payload = (keys["cvk_str"] + pan + ";" + exp + ";" + svc).encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    cvv = resp.decode("ascii")
    assert len(cvv) == 3
    assert cvv.isdigit()
    expected_cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    assert cvv == expected_cvv


def test_cw_cx_no_semicolons_fixed_width(hsm, keys):
    """CW command with no semicolons (fixed width)."""
    pan = "4575272222567122"
    exp = "2512"
    svc = "101"
    payload = (keys["cvk_str"] + pan + exp + svc).encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    cvv = resp.decode("ascii")
    expected_cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    assert cvv == expected_cvv


def test_cw_cx_payload_too_short(hsm, keys):
    """CW command with payload length < 33 bytes raising INVALID_DATA_LENGTH."""
    short_payload = b"U1234567890123456789012345678901"
    with pytest.raises(PayShieldException) as exc_info:
        CWHandler(hsm).handle_payload(short_payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# Edge Case 6: CY/CZ Semicolon & CVV Parsing
# ============================================================================

def test_cy_cz_four_semicolons_success(hsm, keys):
    """CY command with PAN;EXP;SVC;CVV order."""
    pan = "4575272222567122"
    exp = "2512"
    svc = "999"
    cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    payload = (keys["cvk_str"] + pan + ";" + exp + ";" + svc + ";" + cvv).encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_cy_cz_mismatched_cvv(hsm, keys):
    """CY command with mismatched CVV returning error '01'."""
    pan = "4575272222567122"
    exp = "2512"
    svc = "999"
    wrong_cvv = "000"
    payload = (keys["cvk_str"] + pan + ";" + exp + ";" + svc + ";" + wrong_cvv).encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR  # '01'
    assert resp == b""


def test_cy_cz_no_semicolons_cvv_first(hsm, keys):
    """CY command without semicolons (CVVPANEXPSVC order)."""
    pan = "4575272222567122"
    exp = "2512"
    svc = "999"
    cvv = calculate_cvv(keys["clear_cvk"], pan, exp, svc)
    payload = (keys["cvk_str"] + cvv + pan + exp + svc).encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# Additional M3 Command Stress: EE/EF IBM 3624 PIN Offset Verification
# ============================================================================

def test_ee_ef_ibm_3624_offset_success(hsm, keys):
    """EE command IBM 3624 PIN offset verification success."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    dec_table = "0123456789012345"

    # Calculate expected natural PIN and offset
    val_data = pan[-16:].rjust(16, "0")
    val_bytes = unhexlify(val_data)
    import Crypto.Cipher.DES3
    cipher = Crypto.Cipher.DES3.new(keys["clear_pvk"], Crypto.Cipher.DES3.MODE_ECB)
    enc_val = hexlify(cipher.encrypt(val_bytes[:8])).decode("ascii").upper()
    nat_chars = [dec_table[int(c, 16)] for c in enc_val[:4]]
    nat_pin = "".join(nat_chars)

    # Offset = (Customer PIN - Natural PIN) mod 10
    offset = ""
    for c_digit, n_digit in zip(pin, nat_pin):
        offset += str((int(c_digit) - int(n_digit)) % 10)

    # Payload: zpk + pvk + pin_block + fmt("01") + pan + ";" + dec_table + offset
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + ";" + dec_table + offset).encode("ascii")
    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ee_ef_ibm_3624_offset_mismatch(hsm, keys):
    """EE command IBM 3624 PIN offset mismatch returning '01'."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    dec_table = "0123456789012345"
    wrong_offset = "9999"

    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + ";" + dec_table + wrong_offset).encode("ascii")
    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR  # '01'
    assert resp == b""


def test_ee_ef_ibm_3624_custom_dec_table_16_digit_pan_no_semicolon(hsm, keys):
    """EE command with 16-digit PAN and custom decimalization table without semicolons."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    dec_table = "9876543210987654"

    val_data = pan[-16:].rjust(16, "0")
    val_bytes = unhexlify(val_data)
    import Crypto.Cipher.DES3
    cipher = Crypto.Cipher.DES3.new(keys["clear_pvk"], Crypto.Cipher.DES3.MODE_ECB)
    enc_val = hexlify(cipher.encrypt(val_bytes[:8])).decode("ascii").upper()
    nat_chars = [dec_table[int(c, 16)] for c in enc_val[:4]]
    nat_pin = "".join(nat_chars)

    offset = ""
    for c_digit, n_digit in zip(pin, nat_pin):
        offset += str((int(c_digit) - int(n_digit)) % 10)

    # Non-semicolon payload: zpk + pvk + pin_block + fmt("01") + pan + dec_table + offset
    payload = (keys["zpk_str"] + keys["pvk_str"] + pin_block + "01" + pan + dec_table + offset).encode("ascii")
    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


