"""
Empirical Stress Test Harness by Challenger 1 for M3 Commands (Iteration 7).
Tests CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ against edge cases, key schemes,
and framing truncation rules.
"""

import pytest
from binascii import hexlify, unhexlify

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.commands.pin import (
    CAHandler, DCHandler, ECHandler, BAHandler, EEHandler,
    encrypt_pin_block, decrypt_pin_block
)
from pythales.commands.card_verify import CWHandler, CYHandler, calculate_cvv
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def keys(hsm):
    # DES ZPK keys (16 bytes)
    raw_zpk1 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xfe\xdc\xba\x98\x76\x54\x32\x10"
    raw_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

    zpk1_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk1, variant=2)
    zpk2_enc = hsm.lmk_engine.encrypt_under_lmk(raw_zpk2, variant=2)

    zpk1_str = "U" + hexlify(zpk1_enc).decode("ascii").upper()
    zpk2_str = "U" + hexlify(zpk2_enc).decode("ascii").upper()

    # DES PVK key (16 bytes)
    raw_pvk = b"\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    pvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_pvk, variant=3)
    pvk_str = "U" + hexlify(pvk_enc).decode("ascii").upper()

    # DES CVK key (16 bytes)
    raw_cvk = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
    cvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_cvk, variant=4)
    cvk_str = "U" + hexlify(cvk_enc).decode("ascii").upper()

    # TR-31 AES ZPK key (16 bytes AES key)
    raw_aes_zpk = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    hdr_aes = TR31Header("S", 0, "21", "P", "0", "00", "E", b"")
    tr31_zpk_str = TR31KeyBlock.wrap(raw_aes_zpk, hdr_aes, hsm.LMK).decode("ascii")

    # TR-31 CVK key (16 bytes 3DES)
    hdr_cvk = TR31Header("S", 0, "21", "C", "0", "00", "E", b"")
    tr31_cvk_str = TR31KeyBlock.wrap(raw_cvk, hdr_cvk, hsm.LMK).decode("ascii")

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
        "tr31_cvk_str": tr31_cvk_str,
    }


def test_format4_pin_block_roundtrip_19digit_pan(keys):
    """Test ISO 9564-1 Format 4 AES PIN block encryption and decryption with 19-digit PAN."""
    pin = "98765432"
    pan = "4916123456789012345"  # 19 digits
    enc_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)
    assert len(enc_pb) == 32
    dec_pin = decrypt_pin_block(keys["raw_aes_zpk"], enc_pb, "48", pan)
    assert dec_pin == pin


def test_ca_tr31_to_variant_translation(hsm, keys):
    """Test CA command translating PIN block from TR-31 ZPK (Format 4) to LMK Variant ZPK (Format 0)."""
    pin = "4321"
    pan = "4000123456789010"
    src_pb = encrypt_pin_block(keys["raw_aes_zpk"], pin, "48", pan)

    payload = f"{keys['tr31_zpk_str']}{keys['zpk1_str']}12{src_pb}4801{pan}".encode("ascii")
    ca_handler = CAHandler(hsm)
    err, resp = ca_handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
    resp_str = resp.decode("ascii")
    dst_pb = resp_str[:16]
    dst_fmt = resp_str[16:]
    assert dst_fmt == "01"

    dec_pin = decrypt_pin_block(keys["raw_zpk1"], dst_pb, "01", pan)
    assert dec_pin == pin


def test_dc_pvv_verification_success_and_failure(hsm, keys):
    """Test DC command for valid PIN verification and invalid PIN rejection."""
    pin = "5555"
    pan = "4000999988887777"
    pvki = "1"

    from pythales.crypto.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Valid PIN test -> expect Success '00'
    payload_valid = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    dc_handler = DCHandler(hsm)
    err, _ = dc_handler.handle_payload(payload_valid)
    assert err == ErrorCodes.SUCCESS

    # Invalid PIN test -> expect LMK_ERROR '01'
    bad_pb = encrypt_pin_block(keys["raw_zpk1"], "1234", "01", pan)
    payload_invalid = f"{keys['zpk1_str']}{keys['pvk_str']}{bad_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    err_bad, _ = dc_handler.handle_payload(payload_invalid)
    assert err_bad == ErrorCodes.LMK_ERROR


def test_ec_pin_under_lmk_and_interchange_verification(hsm, keys):
    """Test EC command returning PIN under LMK when no PVV, and verifying when PVV present."""
    pin = "2468"
    pan = "4111222233334444"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    # Mode 1: No PVV -> return PIN encrypted under LMK
    payload_mode1 = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}".encode("ascii")
    ec_handler = ECHandler(hsm)
    err1, resp1 = ec_handler.handle_payload(payload_mode1)
    assert err1 == ErrorCodes.SUCCESS
    lmk_pin_block = resp1.decode("ascii")
    assert len(lmk_pin_block) == 16
    dec_pin_lmk = decrypt_pin_block(hsm.LMK, lmk_pin_block, "01", pan)
    assert dec_pin_lmk == pin

    # Mode 2: With PVV -> verify interchange PIN
    from pythales.crypto.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), b"1", pin.encode(), pvk_hex.encode()).decode("ascii")

    payload_mode2 = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}1{calc_pvv}".encode("ascii")
    err2, _ = ec_handler.handle_payload(payload_mode2)
    assert err2 == ErrorCodes.SUCCESS


def test_ba_generate_and_encrypt_clear_pin(hsm, keys):
    """Test BA command with specified clear PIN and random PIN generation."""
    pan = "4000123456789010"
    clear_pin = "8765"

    # Encrypt explicit clear PIN
    payload1 = f"{keys['zpk1_str']}{pan};{clear_pin}".encode("ascii")
    ba_handler = BAHandler(hsm)
    err1, resp1 = ba_handler.handle_payload(payload1)
    assert err1 == ErrorCodes.SUCCESS
    resp_str = resp1.decode("ascii")
    out_pin = resp_str[:4]
    enc_pb = resp_str[4:]
    assert out_pin == clear_pin
    dec_pin = decrypt_pin_block(keys["raw_zpk1"], enc_pb, "01", pan)
    assert dec_pin == clear_pin

    # Random PIN generation (empty payload or length specifier)
    err2, resp2 = ba_handler.handle_payload(b"06")
    assert err2 == ErrorCodes.SUCCESS
    rand_pin = resp2.decode("ascii")
    assert len(rand_pin) == 6 and rand_pin.isdigit()


def test_cw_cy_tr31_cvk_key(hsm, keys):
    """Test CW (Generate) and CY (Verify) with TR-31 wrapped CVK key."""
    pan = "4111111111111111"
    exp_date = "2612"
    service_code = "101"

    # Generate CVV with TR-31 CVK
    cw_payload = f"{keys['tr31_cvk_str']}{pan};{exp_date};{service_code}".encode("ascii")
    cw_handler = CWHandler(hsm)
    err_cw, resp_cw = cw_handler.handle_payload(cw_payload)
    assert err_cw == ErrorCodes.SUCCESS
    cvv = resp_cw.decode("ascii")
    assert len(cvv) == 3 and cvv.isdigit()

    # Verify CVV with TR-31 CVK (Success)
    cy_payload_valid = f"{keys['tr31_cvk_str']}{pan};{exp_date};{service_code};{cvv}".encode("ascii")
    cy_handler = CYHandler(hsm)
    err_cy_val, _ = cy_handler.handle_payload(cy_payload_valid)
    assert err_cy_val == ErrorCodes.SUCCESS

    # Verify CVV with wrong CVV (Failure)
    cy_payload_invalid = f"{keys['tr31_cvk_str']}{pan};{exp_date};{service_code};999".encode("ascii")
    err_cy_inval, _ = cy_handler.handle_payload(cy_payload_invalid)
    assert err_cy_inval == ErrorCodes.LMK_ERROR


def test_tcp_framing_and_error_truncation(keys):
    """Test process_raw_message end-to-end to verify TCP framing envelope and error truncation."""
    header = b"HEAD"
    hsm = HSM(header="HEAD")

    # Valid CW command request
    pan = "4000123456789010"
    exp_date = "2512"
    service_code = "101"
    raw_cmd = b"CW" + f"{keys['cvk_str']}{pan};{exp_date};{service_code}".encode("ascii")
    req_body = header + raw_cmd

    resp_body = hsm.process_raw_message(req_body)

    resp_header = resp_body[:4]
    resp_cmd = resp_body[4:6]
    resp_err = resp_body[6:8]
    resp_data = resp_body[8:]

    assert resp_header == b"HEAD"
    assert resp_cmd == b"CX"
    assert resp_err == b"00"
    assert len(resp_data) == 3

    # Invalid command / error case -> verify truncation rule
    bad_cmd = b"CY" + f"{keys['cvk_str']}{pan};{exp_date};{service_code};000".encode("ascii")  # Wrong CVV
    bad_req_body = header + bad_cmd

    bad_resp_body = hsm.process_raw_message(bad_req_body)

    bad_resp_cmd = bad_resp_body[4:6]
    bad_resp_err = bad_resp_body[6:8]
    bad_resp_data = bad_resp_body[8:]

    assert bad_resp_cmd == b"CZ"
    assert bad_resp_err == b"01"
    assert len(bad_resp_data) == 0  # Truncated!
