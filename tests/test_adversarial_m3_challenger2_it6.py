"""
Adversarial Test Suite - Milestone M3 (PIN & Card Verification Commands)
Challenger 2 - Iteration 6
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
# 1. CA Command Edge Cases & PIN Format Conversions
# ============================================================================

def test_ca_format0_to_format4_cross_translation(hsm, keys):
    """Test CA translating Format 0 (DES) PIN block to Format 4 (AES) PIN block."""
    pan = "4575271111567890"
    pin = "54321"
    src_pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["aes_zpk_u"] + "12" + src_pin_block + "01" + "48" + pan).encode("ascii")
    
    err, resp = CAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pin_block = resp_str[:32]
    dst_fmt = resp_str[32:]
    assert dst_fmt == "48"
    decrypted_pin = decrypt_pin_block(keys["clear_aes_zpk"], dst_pin_block, "48", pan)
    assert decrypted_pin == pin


def test_ca_pin_length_exceeds_max_pin_len(hsm, keys):
    """Test CA raising PIN_LENGTH_OUT_OF_RANGE when clear PIN exceeds max_pin_len parameter."""
    pan = "4575271111567890"
    pin = "12345678"  # length 8
    src_pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    # max PIN len specified as "05"
    payload = (keys["zpk_u"] + keys["zpk2_x"] + "05" + src_pin_block + "01" + pan).encode("ascii")
    
    with pytest.raises(PayShieldException) as exc_info:
        CAHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


def test_ca_invalid_source_pin_block_header(hsm, keys):
    """Test CA handling source PIN block that decrypts to an invalid Format 0 block header."""
    pan = "4575271111567890"
    # Encrypt invalid plaintext block starting with 'F' instead of '0'
    invalid_plain_block = unhexlify("F41234FFFFFFFFFF")
    cipher = Crypto.Cipher.DES3.new(keys["clear_zpk"], Crypto.Cipher.DES3.MODE_ECB)
    acct_12 = pan.rjust(12, "0")[-12:]
    acct_bytes = unhexlify("0000" + acct_12)
    inter_bytes = bytes(a ^ b for a, b in zip(invalid_plain_block, acct_bytes))
    enc_bytes = cipher.encrypt(inter_bytes)
    invalid_pin_block = hexlify(enc_bytes).decode("ascii").upper()

    payload = (keys["zpk_u"] + keys["zpk2_x"] + "12" + invalid_pin_block + "01" + pan).encode("ascii")
    
    with pytest.raises(PayShieldException) as exc_info:
        CAHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_PIN_BLOCK


# ============================================================================
# 2. DC Command Mismatch & Edge Cases
# ============================================================================

def test_dc_pvv_mismatch_returns_lmk_error(hsm, keys):
    """Test DC returning LMK_ERROR ('01') when PVV verification fails."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    wrong_pvv = "9999"
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";1" + wrong_pvv).encode("ascii")
    
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR
    assert resp == b""


def test_dc_pin_decryption_only_without_expected_pvv(hsm, keys):
    """Test DC succeeding when no expected PVV is appended to request."""
    pan = "4575272222567122"
    pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan).encode("ascii")
    
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_dc_format4_aes_verification_with_standard_pan(hsm, keys):
    """Test DC verifying Format 4 AES PIN block with standard 16-digit PAN."""
    pan = "4575272222567122"
    pin = "6543"
    pvki = "2"
    pvk_hex = hexlify(keys["clear_pvk"]).decode("ascii").upper()
    pvv_bytes = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex.encode("ascii"))
    pvv = pvv_bytes.decode("ascii")

    pin_block = encrypt_pin_block(keys["clear_aes_zpk"], pin, "48", pan)
    payload = (keys["aes_zpk_u"] + keys["pvk_u"] + pin_block + "48" + pan + ";" + pvki + pvv).encode("ascii")
    
    err, resp = DCHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


# ============================================================================
# 3. EC Command PIN Block Translation under LMK & Interchange Verification
# ============================================================================

def test_ec_pin_translation_under_lmk_without_pvv(hsm, keys):
    """Test EC translating PIN block from ZPK to LMK when no PVV is supplied."""
    pan = "4575272222567122"
    pin = "7890"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan).encode("ascii")
    
    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    pin_under_lmk = resp.decode("ascii")
    assert len(pin_under_lmk) == 16
    
    # Verify the returned PIN block encrypted under LMK decrypts to the original PIN
    decrypted_pin = decrypt_pin_block(hsm.LMK, pin_under_lmk, "01", pan)
    assert decrypted_pin == pin


def test_ec_pvv_mismatch_returns_lmk_error(hsm, keys):
    """Test EC returning LMK_ERROR ('01') on PVV mismatch."""
    pan = "4575272222567122"
    pin = "7890"
    pin_block = encrypt_pin_block(keys["clear_zpk"], pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";10000").encode("ascii")
    
    err, resp = ECHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR
    assert resp == b""


# ============================================================================
# 4. BA Command Random PIN Generation & Encrypt Clear PIN
# ============================================================================

def test_ba_random_pin_generation_without_zpk(hsm):
    """Test BA generating random PINs when no ZPK is supplied."""
    err, resp = BAHandler(hsm).handle_payload(b"04")
    assert err == ErrorCodes.SUCCESS
    pin = resp.decode("ascii")
    assert len(pin) == 4 and pin.isdigit()

    err, resp = BAHandler(hsm).handle_payload(b"08")
    assert err == ErrorCodes.SUCCESS
    pin8 = resp.decode("ascii")
    assert len(pin8) == 8 and pin8.isdigit()


def test_ba_encrypt_clear_pin_with_zpk(hsm, keys):
    """Test BA encrypting clear PIN under ZPK."""
    pan = "4575272222567122"
    clear_pin = "3456"
    payload = (keys["zpk_u"] + pan + ";" + clear_pin).encode("ascii")
    
    err, resp = BAHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    out_clear_pin = resp_str[:4]
    enc_pin_block = resp_str[4:]
    assert out_clear_pin == clear_pin
    assert len(enc_pin_block) == 16
    
    decrypted_pin = decrypt_pin_block(keys["clear_zpk"], enc_pin_block, "01", pan)
    assert decrypted_pin == clear_pin


def test_ba_invalid_pin_length_specifier(hsm):
    """Test BA raising PIN_LENGTH_OUT_OF_RANGE for pin_len < 4 or > 12."""
    with pytest.raises(PayShieldException) as exc_info:
        BAHandler(hsm).handle_payload(b"02")
    assert exc_info.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE

    with pytest.raises(PayShieldException) as exc_info:
        BAHandler(hsm).handle_payload(b"15")
    assert exc_info.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


# ============================================================================
# 5. EE Command IBM 3624 Offset Verification
# ============================================================================

def test_ee_ibm_3624_offset_verification_success(hsm, keys):
    """Test EE IBM 3624 PIN offset verification success."""
    pan = "4575272222567122"
    dec_table = "0123456789012345"
    validation_data = "4575272222567122"
    pvk_bytes = keys["clear_pvk"]

    # Calculate natural PIN manually for EE verification
    val_bytes = unhexlify(validation_data[:16])
    cipher = Crypto.Cipher.DES3.new(pvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)
    enc_val_hex = hexlify(cipher.encrypt(val_bytes[:8])).decode("ascii").upper()
    
    nat_pin_chars = [dec_table[int(c, 16)] for c in enc_val_hex[:4]]
    nat_pin = "".join(nat_pin_chars)

    # Choose a customer PIN and calculate offset
    customer_pin = "4321"
    offset_chars = []
    for i in range(4):
        diff = (int(customer_pin[i]) - int(nat_pin[i])) % 10
        offset_chars.append(str(diff))
    offset = "".join(offset_chars)

    pin_block = encrypt_pin_block(keys["clear_zpk"], customer_pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";" + dec_table + offset + validation_data).encode("ascii")

    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_ee_ibm_3624_offset_verification_failure(hsm, keys):
    """Test EE returning LMK_ERROR ('01') when IBM 3624 offset verification fails."""
    pan = "4575272222567122"
    dec_table = "0123456789012345"
    validation_data = "4575272222567122"
    wrong_offset = "9999"

    customer_pin = "1234"
    pin_block = encrypt_pin_block(keys["clear_zpk"], customer_pin, "01", pan)
    payload = (keys["zpk_u"] + keys["pvk_u"] + pin_block + "01" + pan + ";" + dec_table + wrong_offset + validation_data).encode("ascii")

    err, resp = EEHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR
    assert resp == b""


# ============================================================================
# 6. CW & CY Card Verification Edge Cases
# ============================================================================

def test_cw_and_cy_19digit_pan_and_13digit_pan(hsm, keys):
    """Test CW and CY with 19-digit PAN and 13-digit PAN."""
    # 19-digit PAN
    pan19 = "4123456789012345678"
    exp19 = "2811"
    svc19 = "101"

    payload_cw = (keys["cvk_u"] + f"{pan19};{exp19};{svc19}").encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload_cw)
    assert err == ErrorCodes.SUCCESS
    cvv19 = resp.decode("ascii")

    payload_cy = (keys["cvk_u"] + f"{pan19};{exp19};{svc19};{cvv19}").encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload_cy)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""

    # 13-digit PAN
    pan13 = "4123456789012"
    exp13 = "2510"
    svc13 = "201"

    payload_cw13 = (keys["cvk_u"] + f"{pan13};{exp13};{svc13}").encode("ascii")
    err, resp = CWHandler(hsm).handle_payload(payload_cw13)
    assert err == ErrorCodes.SUCCESS
    cvv13 = resp.decode("ascii")

    payload_cy13 = (keys["cvk_u"] + f"{pan13};{exp13};{svc13};{cvv13}").encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload_cy13)
    assert err == ErrorCodes.SUCCESS
    assert resp == b""


def test_cy_cvv_mismatch_returns_lmk_error(hsm, keys):
    """Test CY returning LMK_ERROR ('01') when CVV mismatch occurs."""
    pan = "4575272222567122"
    exp = "2612"
    svc = "101"
    wrong_cvv = "999"

    payload = (keys["cvk_u"] + f"{pan};{exp};{svc};{wrong_cvv}").encode("ascii")
    err, resp = CYHandler(hsm).handle_payload(payload)
    assert err == ErrorCodes.LMK_ERROR
    assert resp == b""


def test_cw_payload_too_short_raises_invalid_data_length(hsm):
    """Test CW raising INVALID_DATA_LENGTH ('15') when payload is under minimum length."""
    payload = b"U1234567"
    with pytest.raises(PayShieldException) as exc_info:
        CWHandler(hsm).handle_payload(payload)
    assert exc_info.value.error_code == ErrorCodes.INVALID_DATA_LENGTH


# ============================================================================
# 7. End-to-End HSM Raw Envelope & Error Truncation Processing
# ============================================================================

def test_hsm_process_raw_message_m3_success_and_error_truncation(hsm, keys):
    """Test raw TCP message framing and error truncation rule for M3 commands."""
    header = b"1234"
    hsm_with_header = HSM(header="1234")

    # 1. Success case CW (returns 'CX' + '00' + 3-digit CVV)
    pan = "4575272222567122"
    exp = "2612"
    svc = "101"
    cmd_payload = (keys["cvk_u"] + f"{pan};{exp};{svc}").encode("ascii")
    raw_req = header + b"CW" + cmd_payload
    raw_resp = hsm_with_header.process_raw_message(raw_req)
    
    assert raw_resp.startswith(header + b"CX" + b"00")
    cvv_out = raw_resp[len(header) + 4:].decode("ascii")
    assert len(cvv_out) == 3

    # 2. Error Truncation case CY mismatch (returns 'CZ' + '01' with NO payload)
    wrong_cy_payload = (keys["cvk_u"] + f"{pan};{exp};{svc};999").encode("ascii")
    raw_req_err = header + b"CY" + wrong_cy_payload
    raw_resp_err = hsm_with_header.process_raw_message(raw_req_err)
    
    assert raw_resp_err == header + b"CZ" + b"01"  # Truncated right after Error Code
