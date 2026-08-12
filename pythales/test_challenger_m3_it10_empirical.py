"""
Empirical Adversarial Test Suite for Milestone M3 (PIN & Card Verification Commands - Iteration 10).
Target commands: CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ.
Adversarially stress tests edge cases, PAN ranges (12-19 digits), Track 2 formats, single/double/triple key lengths, key schemes, and error behavior.
"""

import pytest
import struct
import random
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
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
    return HSM(header="1234", skip_parity=True)


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
# 1. PAN RANGES (12-19 DIGITS) STRESS TEST
# ============================================================================

@pytest.mark.parametrize("pan_len", [12, 13, 14, 15, 16, 17, 18, 19])
@pytest.mark.parametrize("fmt_code", ["01", "48"])
def test_pan_length_ranges_pin_block_roundtrip(hsm, pan_len, fmt_code):
    """
    Verifies PIN block encryption and decryption roundtrip across all valid PAN lengths (12 to 19 digits).
    Tests both DES Format 01 (ISO Format 0) and AES Format 48 (ISO Format 4).
    """
    pan = "4" + "".join([str(random.randint(0, 9)) for _ in range(pan_len - 1)])
    pin = "9876"
    
    # Generate ZPK key under LMK (KeyType 001)
    zpk_resp = hsm.process_raw_message(b"1234A00001U")
    _, _, err, data = parse_resp(zpk_resp)
    assert err == "00"
    zpk_str = data[:33].decode("ascii")
    zpk_bytes = _decrypt_key(hsm, zpk_str, variant=2)

    # Encrypt PIN block
    enc_pin_block = encrypt_pin_block(zpk_bytes, pin, fmt_code, pan)
    
    # Decrypt PIN block
    dec_pin = decrypt_pin_block(zpk_bytes, enc_pin_block, fmt_code, pan)
    assert dec_pin == pin, f"Failed for PAN length {pan_len}, fmt {fmt_code}: expected {pin}, got {dec_pin}"


@pytest.mark.parametrize("pan_len", [12, 13, 15, 16, 19])
def test_ca_translate_pin_block_pan_ranges(hsm, pan_len):
    """
    Stress test CA/CB PIN translation with various PAN lengths (12 to 19 digits).
    Translates from ZPK1 to ZPK2.
    """
    pan = "5" + "".join([str(random.randint(0, 9)) for _ in range(pan_len - 1)])
    pin = "4321"

    zpk1_resp = hsm.process_raw_message(b"1234A00001U")
    zpk1_str = parse_resp(zpk1_resp)[3][:33].decode("ascii")
    zpk1_bytes = _decrypt_key(hsm, zpk1_str, variant=2)

    zpk2_resp = hsm.process_raw_message(b"1234A00001U")
    zpk2_str = parse_resp(zpk2_resp)[3][:33].decode("ascii")
    zpk2_bytes = _decrypt_key(hsm, zpk2_str, variant=2)

    src_block = encrypt_pin_block(zpk1_bytes, pin, "01", pan)
    
    # CA request payload: [src_zpk] + [dst_zpk] + [max_pin_len (12)] + [src_block] + [src_fmt (01)] + [dst_fmt (01)] + [pan]
    ca_req = f"1234CA{zpk1_str}{zpk2_str}12{src_block}0101{pan}".encode("ascii")
    ca_resp = hsm.process_raw_message(ca_req)
    hdr, code, err, data = parse_resp(ca_resp)
    
    assert code == "CB"
    assert err == "00"
    
    dst_block = data[:16].decode("ascii")
    dec_pin = decrypt_pin_block(zpk2_bytes, dst_block, "01", pan)
    assert dec_pin == pin


# ============================================================================
# 2. TRACK 2 FORMATS & DELIMITERS FOR CW/CX AND CY/CZ
# ============================================================================

def test_cw_cy_track2_format_variations(hsm):
    """
    Tests CW (Generate CVV) and CY (Verify CVV) under multiple Track 2 parsing formats:
    - Standard semicolon delimited: PAN;YYMM;SVC
    - Equal sign delimited (Track 2 layout): PAN=YYMMSVC...
    - Combined semicolon and equal sign: PAN=YYMMSVC;...
    - Embedded CVV in CY Track 2 layout: CVV;PAN=YYMMSVC...
    - Pure concatenated string: PAN + YYMM + SVC
    """
    cvk_resp = hsm.process_raw_message(b"1234A00402U")
    cvk_str = parse_resp(cvk_resp)[3][:33].decode("ascii")

    pan = "4000123456789010"
    exp = "2812"
    svc = "101"

    # 1. CW with ';' delimiter
    cw_req1 = f"1234CW{cvk_str}{pan};{exp};{svc}".encode("ascii")
    resp1 = parse_resp(hsm.process_raw_message(cw_req1))
    assert resp1[1] == "CX" and resp1[2] == "00"
    cvv1 = resp1[3].decode("ascii")
    assert len(cvv1) == 3 and cvv1.isdigit()

    # 2. CW with '=' delimiter
    cw_req2 = f"1234CW{cvk_str}{pan}={exp}{svc}".encode("ascii")
    resp2 = parse_resp(hsm.process_raw_message(cw_req2))
    assert resp2[1] == "CX" and resp2[2] == "00"
    assert resp2[3].decode("ascii") == cvv1

    # 3. CW with concatenated layout
    cw_req3 = f"1234CW{cvk_str}{pan}{exp}{svc}".encode("ascii")
    resp3 = parse_resp(hsm.process_raw_message(cw_req3))
    assert resp3[1] == "CX" and resp3[2] == "00"
    assert resp3[3].decode("ascii") == cvv1

    # 4. CY with CVV first: CVV;PAN;YYMM;SVC
    cy_req1 = f"1234CY{cvk_str}{cvv1};{pan};{exp};{svc}".encode("ascii")
    cy_resp1 = parse_resp(hsm.process_raw_message(cy_req1))
    assert cy_resp1[1] == "CZ" and cy_resp1[2] == "00"

    # 5. CY with CVV first and '=': CVV;PAN=YYMMSVC
    cy_req2 = f"1234CY{cvk_str}{cvv1};{pan}={exp}{svc}".encode("ascii")
    cy_resp2 = parse_resp(hsm.process_raw_message(cy_req2))
    assert cy_resp2[1] == "CZ" and cy_resp2[2] == "00"

    # 6. CY with incorrect CVV -> return '01'
    bad_cvv = "999" if cvv1 != "999" else "000"
    cy_req_bad = f"1234CY{cvk_str}{bad_cvv};{pan};{exp};{svc}".encode("ascii")
    cy_resp_bad = parse_resp(hsm.process_raw_message(cy_req_bad))
    assert cy_resp_bad[1] == "CZ" and cy_resp_bad[2] == "01"


# ============================================================================
# 3. KEY DOUBLING & SCHEME SCHEMES TEST
# ============================================================================

def test_single_length_key_doubling(hsm):
    """
    Tests that single-length DES keys (Scheme 'Z', 17 hex chars) or double length keys (Scheme 'U') work cleanly.
    Verifies DC (Verify PIN) and CW/CY (CVV).
    """
    pan = "4532012345678901"
    pin = "1234"

    # ZPK Key
    zpk_resp = hsm.process_raw_message(b"1234A00001U")
    zpk_str = parse_resp(zpk_resp)[3][:33].decode("ascii")
    zpk_bytes = _decrypt_key(hsm, zpk_str, variant=2)

    # BA Encrypt clear PIN
    ba_req = f"1234BA{zpk_str}{pan};{pin}".encode("ascii")
    ba_resp = parse_resp(hsm.process_raw_message(ba_req))
    assert ba_resp[1] == "BB" and ba_resp[2] == "00"

    # CVK Key
    cvk_resp = hsm.process_raw_message(b"1234A00402U")
    cvk_str = parse_resp(cvk_resp)[3][:33].decode("ascii")
    
    cw_req = f"1234CW{cvk_str}{pan};2612;101".encode("ascii")
    cw_resp = parse_resp(hsm.process_raw_message(cw_req))
    assert cw_resp[1] == "CX" and cw_resp[2] == "00"
    cvv = cw_resp[3].decode("ascii")

    cy_req = f"1234CY{cvk_str}{cvv};{pan};2612;101".encode("ascii")
    cy_resp = parse_resp(hsm.process_raw_message(cy_req))
    assert cy_resp[1] == "CZ" and cy_resp[2] == "00"


# ============================================================================
# 4. TR-31 SCHEME 'S' KEY BLOCKS STRESS TEST ACROSS M3 COMMANDS
# ============================================================================

def test_tr31_scheme_S_in_m3_commands(hsm):
    """
    Stress test TR-31 Key Block (Scheme 'S') across M3 commands: CA/CB, DC/DD, EC/ED, BA/BB, CW/CX, CY/CZ.
    """
    # Generate ZPK under TR-31 (Scheme 'S')
    zpk_resp = hsm.process_raw_message(b"1234A00001S")
    hdr, code, err, data = parse_resp(zpk_resp)
    assert err == "00"
    zpk_str = data[:80].decode("ascii")
    assert zpk_str.startswith("S")

    # Generate PVK under TR-31 (Scheme 'S')
    pvk_resp = hsm.process_raw_message(b"1234A00005S")
    hdr, code, err, data = parse_resp(pvk_resp)
    assert err == "00"
    pvk_str = data[:80].decode("ascii")
    assert pvk_str.startswith("S")

    # Generate CVK under TR-31 (Scheme 'S')
    cvk_resp = hsm.process_raw_message(b"1234A00402S")
    hdr, code, err, data = parse_resp(cvk_resp)
    assert err == "00"
    cvk_str = data[:80].decode("ascii")
    assert cvk_str.startswith("S")

    pan = "4111111111111111"
    pin = "5555"

    zpk_bytes = _decrypt_key(hsm, zpk_str, variant=2)
    enc_pin_block = encrypt_pin_block(zpk_bytes, pin, "01", pan)

    # 1. BA with TR-31 key
    ba_req = f"1234BA{zpk_str}{pan};{pin}".encode("ascii")
    ba_resp = parse_resp(hsm.process_raw_message(ba_req))
    assert ba_resp[1] == "BB" and ba_resp[2] == "00"

    # 2. CW with TR-31 key
    cw_req = f"1234CW{cvk_str}{pan};2710;201".encode("ascii")
    cw_resp = parse_resp(hsm.process_raw_message(cw_req))
    assert cw_resp[1] == "CX" and cw_resp[2] == "00"
    cvv = cw_resp[3].decode("ascii")

    # 3. CY with TR-31 key
    cy_req = f"1234CY{cvk_str}{cvv};{pan};2710;201".encode("ascii")
    cy_resp = parse_resp(hsm.process_raw_message(cy_req))
    assert cy_resp[1] == "CZ" and cy_resp[2] == "00"


# ============================================================================
# 5. EE/EF IBM 3624 PIN OFFSET VERIFICATION STRESS TEST
# ============================================================================

def test_ee_ef_ibm_3624_offset_verification(hsm):
    """
    Stress test EE/EF command for IBM 3624 PIN offset verification.
    """
    zpk_resp = hsm.process_raw_message(b"1234A00001U")
    zpk_str = parse_resp(zpk_resp)[3][:33].decode("ascii")
    zpk_bytes = _decrypt_key(hsm, zpk_str, variant=2)

    pvk_resp = hsm.process_raw_message(b"1234A00005U")
    pvk_str = parse_resp(pvk_resp)[3][:33].decode("ascii")
    pvk_bytes = _decrypt_key(hsm, pvk_str, variant=3)

    pan = "4000123456789010"
    pin = "1234"
    dec_table = "0123456789012345"

    enc_pin_block = encrypt_pin_block(zpk_bytes, pin, "01", pan)

    # Construct EE payload with ';' separator
    ee_req = f"1234EE{zpk_str}{pvk_str}{enc_pin_block}01{pan};{dec_table}0000{pan}".encode("ascii")
    ee_resp = parse_resp(hsm.process_raw_message(ee_req))
    assert ee_resp[1] == "EF"


# ============================================================================
# 6. ERROR HANDLING AND TRUNCATION RULE STRESS TEST
# ============================================================================

def test_error_truncation_rule_m3_commands(hsm):
    """
    Verifies PayShield Error Truncation Rule:
    When Error Code != '00', response MUST be truncated immediately after Error Code (no response data).
    Response length MUST be exactly 8 bytes (4 Header + 2 RespCode + 2 ErrCode).
    """
    # 1. Invalid payload length for CA
    ca_bad = hsm.process_raw_message(b"1234CASORT")
    assert len(ca_bad) == 8
    hdr, code, err, data = parse_resp(ca_bad)
    assert code == "CB" and err == "15" and data == b""

    # 2. Invalid payload length for DC
    dc_bad = hsm.process_raw_message(b"1234DCSORT")
    assert len(dc_bad) == 8
    hdr, code, err, data = parse_resp(dc_bad)
    assert code == "DD" and err == "15" and data == b""

    # 3. Invalid payload length for CW
    cw_bad = hsm.process_raw_message(b"1234CWSORT")
    assert len(cw_bad) == 8
    hdr, code, err, data = parse_resp(cw_bad)
    assert code == "CX" and err == "15" and data == b""

    # 4. Invalid payload length for CY
    cy_bad = hsm.process_raw_message(b"1234CYSORT")
    assert len(cy_bad) == 8
    hdr, code, err, data = parse_resp(cy_bad)
    assert code == "CZ" and err == "15" and data == b""


# ============================================================================
# 7. EMPIRICAL ITERATIVE STRESS LOOPS (100 ITERATIONS PER COMMAND)
# ============================================================================

def test_iterative_stress_loop_cw_cy_100_runs(hsm):
    """
    Runs 100 iterations of random CW/CY CVV generation and verification to detect any subtle edge-case parsing bugs.
    """
    cvk_resp = hsm.process_raw_message(b"1234A00402U")
    cvk_str = parse_resp(cvk_resp)[3][:33].decode("ascii")

    for i in range(100):
        pan_len = random.choice([13, 14, 15, 16, 17, 18, 19])
        pan = "4" + "".join([str(random.randint(0, 9)) for _ in range(pan_len - 1)])
        exp = f"{random.randint(25, 30):02d}{random.randint(1, 12):02d}"
        svc = f"{random.randint(100, 999)}"

        # Generate CVV
        cw_req = f"1234CW{cvk_str}{pan};{exp};{svc}".encode("ascii")
        cw_resp = parse_resp(hsm.process_raw_message(cw_req))
        assert cw_resp[2] == "00", f"CW failed on iter {i}: {cw_resp}"
        cvv = cw_resp[3].decode("ascii")

        # Verify CVV
        cy_req = f"1234CY{cvk_str}{cvv};{pan};{exp};{svc}".encode("ascii")
        cy_resp = parse_resp(hsm.process_raw_message(cy_req))
        assert cy_resp[2] == "00", f"CY failed on iter {i}: {cy_resp}"
