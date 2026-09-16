"""
Adversarial Stress Test Suite for Milestone M2 (Key Management & TR-31).
"""

import pytest
import os
import struct
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
import Crypto.Cipher.AES

from pythales.hsm import HSM
from pythales.core.frame import MessageFraming
from pythales.core.errors import PayShieldException, ErrorCodes
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header, parse_header
from pythales.crypto.lmk import LMKEngine


@pytest.fixture
def hsm():
    return HSM(header="1234")


def make_request(cmd: bytes, payload: bytes = b"", header: bytes = b"1234") -> bytes:
    body = header + cmd + payload
    return struct.pack("!H", len(body)) + body


# =====================================================================
# 1. TR-31 Key Block Header Tampering, Invalid MAC & Payload Corruption
# =====================================================================

def test_tr31_header_tampering_too_short():
    with pytest.raises(PayShieldException) as exc_info:
        parse_header("S004821TB00N000")  # 15 characters
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


def test_tr31_header_tampering_invalid_length_digits():
    with pytest.raises(PayShieldException) as exc_info:
        parse_header("SXXXX21TB00N0000")
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


def test_tr31_unwrap_short_keyblock():
    kbmk = os.urandom(16)
    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap("S004821TB00N0000SHORT", kbmk)
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


def test_tr31_invalid_mac_payload_tampered():
    kbmk = os.urandom(16)
    clear_key = os.urandom(16)
    hdr = TR31Header(
        version_id="S",
        key_length=48,
        key_usage="21",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E"
    )
    kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk).decode("ascii")
    payload_start = 16
    tampered_char = "0" if kb[payload_start] != "0" else "1"
    tampered_kb = kb[:payload_start] + tampered_char + kb[payload_start + 1:]

    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap(tampered_kb, kbmk)
    assert exc_info.value.error_code in (ErrorCodes.INVALID_KEY_CHECK_VALUE, ErrorCodes.INVALID_KEY_BLOCK)


def test_tr31_invalid_mac_field_tampered():
    kbmk = os.urandom(16)
    clear_key = os.urandom(16)
    hdr = TR31Header(
        version_id="S",
        key_length=48,
        key_usage="21",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E"
    )
    kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk).decode("ascii")
    mac_start = len(kb) - 16
    tampered_char = "0" if kb[mac_start] != "0" else "1"
    tampered_kb = kb[:mac_start] + tampered_char + kb[mac_start + 1:]

    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap(tampered_kb, kbmk)
    assert exc_info.value.error_code in (ErrorCodes.INVALID_KEY_CHECK_VALUE, ErrorCodes.INVALID_KEY_BLOCK)


def test_tr31_corrupt_payload_non_hex():
    kbmk = os.urandom(16)
    hdr_ascii = "S004821TB00N0000"
    corrupt_kb = hdr_ascii + "ZZZZZZZZZZZZZZZZ" + "1234567890ABCDEF"
    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap(corrupt_kb, kbmk)
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


def test_tr31_corrupt_payload_odd_length_hex():
    kbmk = os.urandom(16)
    hdr_ascii = "S004821TB00N0000"
    corrupt_kb = hdr_ascii + "ABCDE" + "1234567890ABCDEF"
    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap(corrupt_kb, kbmk)
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


def test_tr31_corrupt_payload_unaligned_byte_length():
    kbmk = os.urandom(16)
    hdr_str = "S004821TB00N0000"
    corrupt_payload_hex = "11223344556677889900"  # 10 bytes
    mac_data = (hdr_str + corrupt_payload_hex).encode("ascii")
    mac_cipher = Crypto.Cipher.DES3.new(TR31KeyBlock._derive_keys(kbmk)[1][:16], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00"*8)
    mac_pad = 8 - (len(mac_data) % 8)
    if mac_pad != 8:
        mac_data += b"\x00" * mac_pad
    mac_hex = hexlify(mac_cipher.encrypt(mac_data)[-8:]).upper().decode("ascii")
    corrupt_kb = hdr_str + corrupt_payload_hex + mac_hex

    try:
        TR31KeyBlock.unwrap(corrupt_kb, kbmk)
    except PayShieldException as pe:
        assert pe.error_code == ErrorCodes.INVALID_KEY_BLOCK
    except Exception as e:
        pytest.fail(f"TR31KeyBlock.unwrap raised unhandled exception {type(e).__name__}: {e}")


def test_tr31_corrupt_decrypted_payload_bit_length():
    kbmk = os.urandom(16)
    fake_payload = struct.pack(">H", 1024) + os.urandom(14)
    cipher = Crypto.Cipher.DES3.new(TR31KeyBlock._derive_keys(kbmk)[0][:16], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00"*8)
    enc_p = hexlify(cipher.encrypt(fake_payload)).upper().decode("ascii")
    hdr_str = "S004821TB00N0000"
    mac_data = (hdr_str + enc_p).encode("ascii")
    mac_cipher = Crypto.Cipher.DES3.new(TR31KeyBlock._derive_keys(kbmk)[1][:16], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00"*8)
    mac_pad = 8 - (len(mac_data) % 8)
    if mac_pad != 8:
        mac_data += b"\x00" * mac_pad
    mac_hex = hexlify(mac_cipher.encrypt(mac_data)[-8:]).upper().decode("ascii")
    kb = hdr_str + enc_p + mac_hex

    with pytest.raises(PayShieldException) as exc_info:
        TR31KeyBlock.unwrap(kb, kbmk)
    assert exc_info.value.error_code == ErrorCodes.INVALID_KEY_BLOCK


# =====================================================================
# 2. A0 Key Generation (Invalid Scheme, Invalid Type, 6-char KCV Check)
# =====================================================================

def test_a0_invalid_key_scheme(hsm):
    req = make_request(b"A0", b"0000Z")
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)
    assert frame.command_code == "A1"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.INVALID_KEY_SCHEME  # '12'


def test_a0_invalid_key_type(hsm):
    req = make_request(b"A0", b"0999U")
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)
    assert frame.command_code == "A1"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.INVALID_KEY_TYPE  # '02'


def test_a0_6_char_kcv_check(hsm):
    schemes = ["U", "T", "S", "X", "Y"]
    key_types = ["000", "001", "002", "003", "005", "00A", "00B", "402"]

    for kt in key_types:
        for sch in schemes:
            payload = f"0{kt}{sch}".encode("ascii")
            req = make_request(b"A0", payload)
            resp_raw = hsm.process_raw_message(req)
            frame = MessageFraming.parse_request(resp_raw, header_length=4)

            assert frame.command_code == "A1", f"Failed for {kt} {sch}"
            err_code = frame.raw_body[2:4].decode("ascii")
            assert err_code == ErrorCodes.SUCCESS, f"Error {err_code} for {kt} {sch}"

            resp_data = frame.raw_body[4:].decode("ascii")
            kcv = resp_data[-6:]
            assert len(kcv) == 6, f"KCV length is not 6 chars: {kcv}"
            assert all(c in "0123456789ABCDEF" for c in kcv), f"KCV is not hex: {kcv}"


def test_a0_mode_1_zmk_export(hsm):
    zmk_req = make_request(b"A0", b"0000U")
    zmk_resp = hsm.process_raw_message(zmk_req)
    zmk_frame = MessageFraming.parse_request(zmk_resp, header_length=4)
    zmk_hex = zmk_frame.raw_body[4:].decode("ascii")[:33]

    payload = f"1001U;0{zmk_hex}".encode("ascii")
    req = make_request(b"A0", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "A1"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS
    kcv = frame.raw_body[4:].decode("ascii")[-6:]
    assert len(kcv) == 6


# =====================================================================
# 3. A6 Key Import under ZMK with DEK Variant Protection ('00B' / '008')
# =====================================================================

def test_a6_dek_variant_00b_under_variant_lmk_succeeds(hsm):
    zmk_raw = os.urandom(16)
    zmk_enc = hsm.lmk_engine.encrypt_under_lmk(zmk_raw, variant=1)
    zmk_hex = "U" + hexlify(zmk_enc).upper().decode("ascii")

    dek_raw = os.urandom(16)
    zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    dek_zmk_enc = zmk_cipher.encrypt(dek_raw)
    dek_zmk_hex = "U" + hexlify(dek_zmk_enc).upper().decode("ascii")

    payload = f"00B{zmk_hex}{dek_zmk_hex}U".encode("ascii")
    req = make_request(b"A6", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "A7"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS


def test_a6_008_is_zak_and_variant_transport_succeeds(hsm):
    zmk_raw = os.urandom(16)
    zmk_enc = hsm.lmk_engine.encrypt_under_lmk(zmk_raw, variant=1)
    zmk_hex = "U" + hexlify(zmk_enc).upper().decode("ascii")

    dek_raw = os.urandom(16)
    zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    dek_zmk_enc = zmk_cipher.encrypt(dek_raw)
    dek_zmk_hex = "T" + hexlify(dek_zmk_enc + os.urandom(8)).upper().decode("ascii")

    payload = f"008{zmk_hex}{dek_zmk_hex}T".encode("ascii")
    req = make_request(b"A6", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "A7"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS


def test_a6_dek_with_tr31_scheme_S_succeeds(hsm):
    zmk_raw = os.urandom(16)
    zmk_enc = hsm.lmk_engine.encrypt_under_lmk(zmk_raw, variant=1)
    zmk_hex = "U" + hexlify(zmk_enc).upper().decode("ascii")

    dek_raw = os.urandom(16)
    hdr = TR31Header(
        version_id="S",
        key_length=48,
        key_usage="00",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E"
    )
    tr31_kb = TR31KeyBlock.wrap(dek_raw, hdr, zmk_raw).decode("ascii")

    payload = f"00B{zmk_hex}{tr31_kb}S".encode("ascii")
    req = make_request(b"A6", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "A7"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS
    kcv = frame.raw_body[4:].decode("ascii")[-6:]
    assert kcv == LMKEngine.generate_kcv(dek_raw)


def test_a6_non_dek_under_zmk_scheme_U_succeeds(hsm):
    zmk_raw = os.urandom(16)
    zmk_enc = hsm.lmk_engine.encrypt_under_lmk(zmk_raw, variant=1)
    zmk_hex = "U" + hexlify(zmk_enc).upper().decode("ascii")

    zpk_raw = os.urandom(16)
    zmk_cipher = Crypto.Cipher.DES3.new(zmk_raw[:16], Crypto.Cipher.DES3.MODE_ECB)
    zpk_zmk_enc = zmk_cipher.encrypt(zpk_raw)
    zpk_zmk_hex = "U" + hexlify(zpk_zmk_enc).upper().decode("ascii")

    payload = f"001{zmk_hex}{zpk_zmk_hex}U".encode("ascii")
    req = make_request(b"A6", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "A7"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS
    kcv = frame.raw_body[4:].decode("ascii")[-6:]
    assert kcv == LMKEngine.generate_kcv(zpk_raw)


# =====================================================================
# 4. GI/GJ Key Scheme Translation
# =====================================================================

def test_gi_variant_to_tr31(hsm):
    raw_key = os.urandom(16)
    enc_lmk = hsm.lmk_engine.encrypt_under_lmk(raw_key, variant=2)
    key_u_hex = "U" + hexlify(enc_lmk).upper().decode("ascii")

    payload = f"001US{key_u_hex}".encode("ascii")
    req = make_request(b"GI", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "GJ"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS
    resp_str = frame.raw_body[4:].decode("ascii")
    kcv = resp_str[-6:]
    assert kcv == LMKEngine.generate_kcv(raw_key)
    kb_str = resp_str[:-6]
    assert kb_str.startswith("S")
    hdr, unwrapped_key = TR31KeyBlock.unwrap(kb_str, hsm.LMK)
    assert unwrapped_key == raw_key


def test_gi_tr31_to_variant(hsm):
    raw_key = os.urandom(16)
    hdr = TR31Header(
        version_id="S",
        key_length=48,
        key_usage="21",
        algorithm="T",
        mode_of_use="B",
        key_version="00",
        exportability="E"
    )
    kb = TR31KeyBlock.wrap(raw_key, hdr, hsm.LMK).decode("ascii")

    payload = f"001SU{kb}".encode("ascii")
    req = make_request(b"GI", payload)
    resp_raw = hsm.process_raw_message(req)
    frame = MessageFraming.parse_request(resp_raw, header_length=4)

    assert frame.command_code == "GJ"
    err_code = frame.raw_body[2:4].decode("ascii")
    assert err_code == ErrorCodes.SUCCESS
    resp_str = frame.raw_body[4:].decode("ascii")
    kcv = resp_str[-6:]
    assert kcv == LMKEngine.generate_kcv(raw_key)
    key_u_hex = resp_str[:-6]
    assert key_u_hex.startswith("U")
    dec_raw = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_u_hex[1:]), variant=2)
    assert dec_raw == raw_key


def test_gi_roundtrip(hsm):
    raw_key = os.urandom(16)
    enc_lmk = hsm.lmk_engine.encrypt_under_lmk(raw_key, variant=2)
    key_u_hex = "U" + hexlify(enc_lmk).upper().decode("ascii")

    # Step 1: GI U -> S
    p1 = f"001US{key_u_hex}".encode("ascii")
    req1 = make_request(b"GI", p1)
    f1 = MessageFraming.parse_request(hsm.process_raw_message(req1), header_length=4)
    assert f1.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    kb_s = f1.raw_body[4:].decode("ascii")[:-6]

    # Step 2: GI S -> U
    p2 = f"001SU{kb_s}".encode("ascii")
    req2 = make_request(b"GI", p2)
    f2 = MessageFraming.parse_request(hsm.process_raw_message(req2), header_length=4)
    assert f2.raw_body[2:4].decode("ascii") == ErrorCodes.SUCCESS
    key_u_2 = f2.raw_body[4:].decode("ascii")[:-6]

    dec_raw_2 = hsm.lmk_engine.decrypt_under_lmk(unhexlify(key_u_2[1:]), variant=2)
    assert dec_raw_2 == raw_key
