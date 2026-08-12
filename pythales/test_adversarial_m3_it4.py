"""
Adversarial Stress Test Harness for M3 Commands (Iteration 4).
Focuses on finding failure modes, edge cases, spec non-compliances, and bugs in CA, DC, EC, BA, EE, CW, CY.
"""

import pytest
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.commands.pin import (
    CAHandler, DCHandler, ECHandler, BAHandler, EEHandler,
    encrypt_pin_block, decrypt_pin_block, _extract_pin_block_and_fmt, _parse_pan_and_pvv
)
from pythales.commands.card_verify import CWHandler, CYHandler, calculate_cvv
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


@pytest.fixture
def hsm():
    return HSM()


@pytest.fixture
def keys(hsm):
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

    raw_aes_zpk = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    hdr_aes = TR31Header("S", 0, "21", "A", "B", "00", "E", b"")
    tr31_zpk_str = TR31KeyBlock.wrap(raw_aes_zpk, hdr_aes, hsm.LMK).decode("ascii")

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
# CHALLENGE 1: Format 4 PIN Block Extraction Ambiguity Bug Test
# ============================================================================

def test_challenge_format4_pin_block_extraction_ambiguity(keys):
    """
    Construct a 32-hex Format 4 PIN block where bytes at offset 16..18 happen to be '01'
    and bytes at offset 18..30 happen to be digits.
    Verify if _extract_pin_block_and_fmt misidentifies it as 16-hex Format 0.
    """
    ambiguous_pb32 = "A" * 16 + "01" + "123456789012" + "BB"
    fmt = "48"
    dst_fmt = "01"
    pan = "4000123456789010"

    rem = ambiguous_pb32 + fmt + dst_fmt + pan

    extracted_pb, extracted_fmt, remaining = _extract_pin_block_and_fmt(rem)

    assert len(extracted_pb) == 32, f"Expected 32-hex Format 4 PIN block, got {len(extracted_pb)}-hex: {extracted_pb}"
    assert extracted_fmt == "48", f"Expected format '48', got '{extracted_fmt}'"


# ============================================================================
# CHALLENGE 2: CW Track 2 Data with '=' or leading ';'
# ============================================================================

def test_challenge_cw_track2_with_equals(hsm, keys):
    """
    Test CW command with Track 2 data containing '=' separator (PAN=YYMMSVC).
    e.g., 4000123456789010=25121010000
    """
    pan = "4000123456789010"
    exp_date = "2512"
    service_code = "101"
    track2 = f"{pan}={exp_date}{service_code}00000"

    cw_payload = f"{keys['cvk_str']}{track2}".encode("ascii")
    cw_handler = CWHandler(hsm)

    try:
        err, resp = cw_handler.handle_payload(cw_payload)
        assert err == ErrorCodes.SUCCESS
        cvv = resp.decode("ascii")
        ref_cvv = calculate_cvv(keys["raw_cvk"], pan, exp_date, service_code)
        assert cvv == ref_cvv
    except Exception as e:
        pytest.fail(f"CW failed on Track 2 data with '=': {e}")


def test_challenge_cw_track2_leading_semicolon(hsm, keys):
    """
    Test CW command with Track 2 data starting with ';'
    e.g., ;4000123456789010=2512101000000?
    """
    pan = "4000123456789010"
    exp_date = "2512"
    service_code = "101"
    track2 = f";{pan}={exp_date}{service_code}00000?"

    cw_payload = f"{keys['cvk_str']}{track2}".encode("ascii")
    cw_handler = CWHandler(hsm)

    try:
        err, resp = cw_handler.handle_payload(cw_payload)
        assert err == ErrorCodes.SUCCESS
        cvv = resp.decode("ascii")
        ref_cvv = calculate_cvv(keys["raw_cvk"], pan, exp_date, service_code)
        assert cvv == ref_cvv
    except Exception as e:
        pytest.fail(f"CW failed on Track 2 data with leading ';': {e}")


# ============================================================================
# CHALLENGE 3: CY Track 2 Data with '=' or leading ';'
# ============================================================================

def test_challenge_cy_track2_formats(hsm, keys):
    """
    Test CY command with Track 2 data formats and CVV verification.
    """
    pan = "4000123456789010"
    exp_date = "2512"
    service_code = "101"
    ref_cvv = calculate_cvv(keys["raw_cvk"], pan, exp_date, service_code)

    payload1 = f"{keys['cvk_str']}{pan};{exp_date};{service_code};{ref_cvv}".encode("ascii")
    cy_handler = CYHandler(hsm)
    err1, _ = cy_handler.handle_payload(payload1)
    assert err1 == ErrorCodes.SUCCESS

    payload2 = f"{keys['cvk_str']}{ref_cvv};{pan}={exp_date}{service_code}00000".encode("ascii")
    err2, _ = cy_handler.handle_payload(payload2)
    assert err2 == ErrorCodes.SUCCESS


# ============================================================================
# CHALLENGE 4: DC & EC Track 2 Parsing with '='
# ============================================================================

def test_challenge_dc_track2_with_equals(hsm, keys):
    """
    Test DC command when PAN payload contains Track 2 data with '=' before PVKI and PVV.
    e.g. PAN=YYMMSVC;11234
    """
    pin = "1234"
    pan = "4000123456789010"
    pvki = "1"

    from pynblock.tools import get_visa_pvv
    pvk_hex = hexlify(keys["raw_pvk"]).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}=2512101;{pvki}{calc_pvv}".encode("ascii")
    dc_handler = DCHandler(hsm)
    err, resp = dc_handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS, f"DC failed on Track 2 payload with '=': err={err}"


# ============================================================================
# CHALLENGE 5: BA Invalid Clear PIN Length (< 4 digits)
# ============================================================================

def test_challenge_ba_invalid_clear_pin_length(hsm, keys):
    """
    Test BA command when clear PIN specified is 3 digits (invalid).
    Should raise PIN_LENGTH_OUT_OF_RANGE or handle cleanly.
    """
    pan = "4000123456789010"
    payload = f"{keys['zpk1_str']}{pan};123".encode("ascii")
    handler = BAHandler(hsm)
    with pytest.raises(PayShieldException) as exc:
        handler.handle_payload(payload)
    assert exc.value.error_code == ErrorCodes.PIN_LENGTH_OUT_OF_RANGE


# ============================================================================
# CHALLENGE 6: EE 16-Digit PAN without Semicolon in Format 0
# ============================================================================

def test_challenge_ee_16digit_pan_format0_no_semicolon(hsm, keys):
    """
    Test EE command when PAN is 16 digits without semicolon delimiter in Format 0.
    rem = 16-digit PAN + 16-digit DEC_TABLE + 4-digit OFFSET (36 chars total).
    """
    pin = "1234"
    pan = "4000123456789010"
    dec_table = "0123456789012345"

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    from Crypto.Cipher import DES3
    val_data = pan.rjust(16, "0")
    cipher = DES3.new(keys["raw_pvk"][:16], DES3.MODE_ECB)
    enc_val = hexlify(cipher.encrypt(unhexlify(val_data[:16])[:8])).decode("ascii").upper()
    nat_pin_chars = [dec_table[int(c, 16)] for c in enc_val[:4]]
    nat_pin = "".join(nat_pin_chars)
    offset = "".join([str((int(pin[i]) - int(nat_pin[i])) % 10) for i in range(4)])

    payload = f"{keys['zpk1_str']}{keys['pvk_str']}{enc_pb}01{pan}{dec_table}{offset}".encode("ascii")
    ee_handler = EEHandler(hsm)
    err, resp = ee_handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS, f"EE failed on 16-digit PAN without semicolon: err={err}"


# ============================================================================
# CHALLENGE 7: Unsupported PIN Block Format Code in CA
# ============================================================================

def test_challenge_ca_unsupported_pin_format(hsm, keys):
    """
    Test CA command with unsupported PIN block format (e.g., '99').
    Should raise INVALID_PIN_BLOCK_FORMAT (23).
    """
    pin = "1234"
    pan = "4000123456789010"
    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{keys['zpk2_str']}12{enc_pb}9999{pan}".encode("ascii")
    handler = CAHandler(hsm)
    with pytest.raises(PayShieldException) as exc:
        handler.handle_payload(payload)
    assert exc.value.error_code == ErrorCodes.INVALID_PIN_BLOCK_FORMAT


# ============================================================================
# CHALLENGE 8: DC Single-Length PVK Key (8-byte / 16-hex)
# ============================================================================

def test_challenge_dc_single_length_pvk(hsm, keys):
    """
    Test DC command with single-length PVK key (8 bytes / 16 hex chars).
    """
    pin = "1234"
    pan = "4000123456789010"
    pvki = "1"
    raw_single_pvk = b"\x12\x34\x56\x78\x90\xab\xcd\xef"
    pvk_enc = hsm.lmk_engine.encrypt_under_lmk(raw_single_pvk, variant=3)
    single_pvk_str = "Z" + hexlify(pvk_enc).decode("ascii").upper()

    from pynblock.tools import get_visa_pvv
    pvk_hex = (hexlify(raw_single_pvk) * 2).decode("ascii").upper()
    calc_pvv = get_visa_pvv(pan.encode(), pvki.encode(), pin.encode(), pvk_hex.encode()).decode("ascii")

    enc_pb = encrypt_pin_block(keys["raw_zpk1"], pin, "01", pan)

    payload = f"{keys['zpk1_str']}{single_pvk_str}{enc_pb}01{pan}{pvki}{calc_pvv}".encode("ascii")
    dc_handler = DCHandler(hsm)
    err, _ = dc_handler.handle_payload(payload)

    assert err == ErrorCodes.SUCCESS
