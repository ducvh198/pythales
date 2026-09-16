"""Grounded compatibility checks from Core Host Commands Guide V1.9b Rev C.

Root of trust: NotebookLM notebook 623c4820-0d11-4da9-81c4-3aa9f5386a4a.
The tests intentionally cover observable host-protocol behavior, not claims of
certification against physical payShield hardware.
"""

from binascii import hexlify

import Crypto.Cipher.DES3
import pytest

from pythales.commands.key_mgmt import KEY_TYPE_VARIANTS
from pythales.core.errors import ErrorCodes
from pythales.core.frame import MessageFraming
from pythales.hsm import HSM


def test_standard_error_code_meanings_from_chapter_12():
    assert ErrorCodes.INVALID_INPUT_DATA == "15"
    assert ErrorCodes.NOT_AUTHORIZED == "17"
    assert ErrorCodes.INTERNAL_HARDWARE_ERROR == "41"
    assert ErrorCodes.COMMAND_DISABLED == "68"
    assert ErrorCodes.DATA_LENGTH_ERROR == "80"
    assert ErrorCodes.REQUEST_DATA_PARITY_ERROR == "90"
    assert ErrorCodes.INVALID_KEY_USAGE == "A6"
    assert ErrorCodes.INVALID_ALGORITHM == "A7"
    assert ErrorCodes.INVALID_MODE_OF_USE == "A8"
    assert ErrorCodes.REPEATED_OPTIONAL_BLOCK == "BC"


def test_configured_header_is_transparent_and_echoed_unchanged():
    hsm = HSM(header="SSSS")
    response = hsm.process_raw_message(b"ABCDNC")
    assert response.startswith(b"ABCDND00")


def test_framing_preserves_command_specific_error_diagnostics():
    response = MessageFraming.format_response(b"HDR", "ZZ", "15", b"DETAIL")
    assert response == b"HDRZZ15DETAIL"


def test_core_key_type_names_are_not_conflated():
    assert KEY_TYPE_VARIANTS["008"] != KEY_TYPE_VARIANTS["00B"]
    assert "30B" in KEY_TYPE_VARIANTS


def test_a6_variant_lmk_allows_00b_dek_in_variant_transport():
    hsm = HSM(header="HDR1")
    zmk_clear = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    zmk_lmk = hsm.lmk_engine.encrypt_under_lmk(
        zmk_clear, variant=KEY_TYPE_VARIANTS["000"]
    )
    zmk_field = "U" + hexlify(zmk_lmk).decode("ascii").upper()

    dek_clear = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    cipher = Crypto.Cipher.DES3.new(zmk_clear, Crypto.Cipher.DES3.MODE_ECB)
    dek_field = "U" + hexlify(cipher.encrypt(dek_clear)).decode("ascii").upper()

    response = hsm.process_raw_message(
        ("HDR1A600B" + zmk_field + dek_field + "U").encode("ascii")
    )
    assert response.startswith(b"HDR1A700U")


def test_a6_rejects_transport_scheme_as_lmk_output_scheme():
    hsm = HSM(header="HDR1")
    zmk_clear = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    zmk_lmk = hsm.lmk_engine.encrypt_under_lmk(
        zmk_clear, variant=KEY_TYPE_VARIANTS["000"]
    )
    zmk_field = "U" + hexlify(zmk_lmk).decode("ascii").upper()
    key_clear = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    key_field = "U" + hexlify(
        Crypto.Cipher.DES3.new(zmk_clear, Crypto.Cipher.DES3.MODE_ECB).encrypt(key_clear)
    ).decode("ascii").upper()

    response = hsm.process_raw_message(
        ("HDR1A6001" + zmk_field + key_field + "X").encode("ascii")
    )
    assert response == b"HDR1A726"


def _variant_data_key(hsm):
    clear = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    encrypted = hsm.lmk_engine.encrypt_under_lmk(
        clear, variant=KEY_TYPE_VARIANTS["00B"]
    )
    return clear, b"U" + hexlify(encrypted).upper()


def test_m0_m2_core_wire_format_ecb_has_no_implicit_padding():
    hsm = HSM(header="HDR1")
    clear_key, key_field = _variant_data_key(hsm)
    plaintext = bytes.fromhex("0011223344556677")
    request_payload = b"00" + b"11" + b"00B" + key_field + b"0008" + hexlify(plaintext)

    encrypted_response = hsm.process_raw_message(b"HDR1M0" + request_payload)
    cipher = Crypto.Cipher.DES3.new(
        clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_ECB
    ).encrypt(plaintext)
    assert encrypted_response == b"HDR1M1000008" + hexlify(cipher).upper()

    decrypt_payload = b"00" + b"11" + b"00B" + key_field + b"0008" + hexlify(cipher)
    decrypted_response = hsm.process_raw_message(b"HDR1M2" + decrypt_payload)
    assert decrypted_response == b"HDR1M3000008" + hexlify(plaintext).upper()


def test_m0_core_wire_format_cbc_returns_chaining_iv():
    hsm = HSM(header="HDR1")
    clear_key, key_field = _variant_data_key(hsm)
    iv = bytes.fromhex("0102030405060708")
    plaintext = bytes.fromhex("0011223344556677")
    request_payload = (
        b"01" + b"11" + b"00B" + key_field + hexlify(iv) + b"0008" + hexlify(plaintext)
    )
    cipher = Crypto.Cipher.DES3.new(
        clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_CBC, iv=iv
    ).encrypt(plaintext)

    response = hsm.process_raw_message(b"HDR1M0" + request_payload)
    assert response == b"HDR1M100" + hexlify(cipher).upper() + b"0008" + hexlify(cipher).upper()


def test_m0_core_wire_length_errors_follow_chapter_12_rule():
    hsm = HSM(header="HDR1")
    _, key_field = _variant_data_key(hsm)
    prefix = b"HDR1M0001100B" + key_field
    assert hsm.process_raw_message(prefix + b"0008" + b"00112233445566") == b"HDR1M180"
    assert hsm.process_raw_message(prefix + b"0008" + b"001122334455667788") == b"HDR1M115"


def test_m0_rejects_unaligned_ecb_and_variant_ctr_ff1():
    hsm = HSM(header="HDR1")
    _, key_field = _variant_data_key(hsm)
    ecb = b"HDR1M0001100B" + key_field + b"0007" + b"00112233445566"
    ctr = b"HDR1M0061100B" + key_field + b"0000000000000000" + b"000008" + b"0001" + b"AA"
    ff1 = b"HDR1M011A00001100B" + key_field + b"0002" + b"1234"
    assert hsm.process_raw_message(ecb) == b"HDR1M106"
    assert hsm.process_raw_message(ctr) == b"HDR1M1D2"
    assert hsm.process_raw_message(ff1) == b"HDR1M1D1"


def test_tr31_version_b_known_block_unwraps_with_r_transport_prefix():
    from pythales.crypto.keyblock import TR31KeyBlock

    kbpk = b"\xAB" * 16
    key_block = (
        "R"
        "B0096P0TE00N0000"
        "471D4FBE35E5865BDE20DBF4C1550316"
        "1F55D681170BF8DD14D01B6822EF8550"
        "CB67C569DE8AC048"
    )
    header, clear_key = TR31KeyBlock.unwrap(key_block, kbpk)
    assert header.version_id == "B"
    assert header.key_usage == "P0"
    assert clear_key == b"\xCD" * 16


def test_keyblock_module_can_load_without_optional_psec(monkeypatch):
    import builtins
    import importlib.util
    from pathlib import Path

    real_import = builtins.__import__

    def import_without_psec(name, *args, **kwargs):
        if name == "psec" or name.startswith("psec."):
            raise ModuleNotFoundError("No module named 'psec'", name="psec")
        return real_import(name, *args, **kwargs)

    module_spec = importlib.util.find_spec("pythales.crypto.keyblock")
    module_path = Path(module_spec.origin) if module_spec and module_spec.origin else (Path(__file__).resolve().parent.parent / "pythales" / "crypto" / "keyblock.py")
    monkeypatch.setattr(builtins, "__import__", import_without_psec)
    spec = importlib.util.spec_from_file_location("_keyblock_without_psec", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.psec_tr31 is None
    with pytest.raises(module.PayShieldException) as exc:
        module._require_psec_tr31()
    assert exc.value.error_code == module.ErrorCodes.INTERNAL_HARDWARE_ERROR


def test_m2_single_des_decryption():
    """Verify M2 single-DES key decryption (8-byte key, scheme Z and raw 16-hex) works without crashing."""
    import Crypto.Cipher.DES

    hsm = HSM(header="HDR1")
    clear_key = bytes.fromhex("0123456789ABCDEF")
    encrypted_key = hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=KEY_TYPE_VARIANTS["00B"])
    key_field_z = b"Z" + hexlify(encrypted_key).upper()
    key_field_raw = hexlify(encrypted_key).upper()

    plaintext = b"HELLO123"
    cipher_des = Crypto.Cipher.DES.new(clear_key, Crypto.Cipher.DES.MODE_ECB)
    ciphertext = cipher_des.encrypt(plaintext)

    # 1. Scheme Z
    req_z = b"HDR1M2001100B" + key_field_z + b"0008" + hexlify(ciphertext).upper()
    resp_z = hsm.process_raw_message(req_z)
    assert resp_z == b"HDR1M3000008" + hexlify(plaintext).upper()

    # 2. Raw 16-hex without scheme
    req_raw = b"HDR1M2001100B" + key_field_raw + b"0008" + hexlify(ciphertext).upper()
    resp_raw = hsm.process_raw_message(req_raw)
    assert resp_raw == b"HDR1M3000008" + hexlify(plaintext).upper()


def test_m2_command_specific_error_codes():
    """Verify M2 returns payShield 10K command-specific error codes (02, 03, 04, 05, 06, 67, 80, 15)."""
    hsm = HSM(header="HDR1")
    _, key_field = _variant_data_key(hsm)

    # Error 02: Invalid Mode Flag (e.g. '99')
    assert hsm.process_raw_message(b"HDR1M2991100B" + key_field + b"00080102030405060708") == b"HDR1M302"

    # Error 67: Command Not Licensed (Visa modes '04', '13')
    assert hsm.process_raw_message(b"HDR1M2041100B" + key_field + b"00080102030405060708") == b"HDR1M367"
    assert hsm.process_raw_message(b"HDR1M2131100B" + key_field + b"00080102030405060708") == b"HDR1M367"

    # Error 03: Invalid Input Format Flag (format '2' is invalid for decryption input)
    assert hsm.process_raw_message(b"HDR1M2002100B" + key_field + b"00080102030405060708") == b"HDR1M303"
    assert hsm.process_raw_message(b"HDR1M2009100B" + key_field + b"00080102030405060708") == b"HDR1M303"

    # Error 04: Invalid Output Format Flag (format '9' is invalid)
    assert hsm.process_raw_message(b"HDR1M2001900B" + key_field + b"00080102030405060708") == b"HDR1M304"

    # Error 05: Invalid Key Type
    assert hsm.process_raw_message(b"HDR1M20011999" + key_field + b"00080102030405060708") == b"HDR1M305"

    # Error 06: Unaligned block length in ECB mode (not multiple of 8)
    assert hsm.process_raw_message(b"HDR1M2001100B" + key_field + b"000701020304050607") == b"HDR1M306"

    # Error 06: Message length exceeds 32000 bytes (0x7D00)
    assert hsm.process_raw_message(b"HDR1M2001100B" + key_field + b"7D010102030405060708") == b"HDR1M306"

    # Error 80: Message length is 0
    assert hsm.process_raw_message(b"HDR1M2001100B" + key_field + b"0000") == b"HDR1M380"

    # Error 80: Payload shorter than declared message length
    assert hsm.process_raw_message(b"HDR1M2001100B" + key_field + b"000801020304") == b"HDR1M380"

    # Error 15: Payload longer than declared message length
    assert hsm.process_raw_message(b"HDR1M2001100B" + key_field + b"0008010203040506070899") == b"HDR1M315"


def test_m2_bdk_key_types_support():
    """Verify BDK Key Types ('009', '609', '809', '909') are accepted by M2."""
    hsm = HSM(header="HDR1")
    clear_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    plaintext = b"DATA1234"

    for kt in ("009", "609", "809", "909"):
        enc_key = hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=KEY_TYPE_VARIANTS[kt])
        key_field = b"U" + hexlify(enc_key).upper()
        cipher = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)

        req = b"HDR1M20011" + kt.encode("ascii") + key_field + b"0008" + hexlify(ciphertext).upper()
        resp = hsm.process_raw_message(req)
        assert resp == b"HDR1M3000008" + hexlify(plaintext).upper()


def test_m2_m3_output_iv_rules_per_mode():
    """
    Verify Output IV presence in M3 response:
    - Present for 01 (CBC), 02 (CFB8), 03 (CFB64), 05 (OFB), 06 (CTR)
    - Omitted for 00 (ECB), 11 (FF1)
    """
    hsm = HSM(header="HDR1")
    clear_key, key_field = _variant_data_key(hsm)
    plaintext = b"BLOCKONEBLOCKTWO"  # 16 bytes = 2 DES blocks
    iv = bytes.fromhex("A1B2C3D4E5F60718")

    # 1. CBC (01): Output IV in M3 is the last ciphertext block
    cipher_cbc = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_CBC, iv=iv)
    ct_cbc = cipher_cbc.encrypt(plaintext)
    expected_out_iv = ct_cbc[-8:]
    req_cbc = b"HDR1M2011100B" + key_field + hexlify(iv).upper() + b"0010" + hexlify(ct_cbc).upper()
    resp_cbc = hsm.process_raw_message(req_cbc)
    assert resp_cbc == b"HDR1M300" + hexlify(expected_out_iv).upper() + b"0010" + hexlify(plaintext).upper()

    # 2. CFB8 (02): Output IV in M3 is (iv + ciphertext)[-8:]
    cipher_cfb8 = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=8)
    ct_cfb8 = cipher_cfb8.encrypt(plaintext)
    expected_cfb8_iv = (iv + ct_cfb8)[-8:]
    req_cfb8 = b"HDR1M2021100B" + key_field + hexlify(iv).upper() + b"0010" + hexlify(ct_cfb8).upper()
    resp_cfb8 = hsm.process_raw_message(req_cfb8)
    assert resp_cfb8 == b"HDR1M300" + hexlify(expected_cfb8_iv).upper() + b"0010" + hexlify(plaintext).upper()

    # 3. CFB64 (03): Output IV in M3 is (iv + ciphertext)[-8:]
    cipher_cfb64 = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_CFB, iv=iv, segment_size=64)
    ct_cfb64 = cipher_cfb64.encrypt(plaintext)
    expected_cfb64_iv = (iv + ct_cfb64)[-8:]
    req_cfb64 = b"HDR1M2031100B" + key_field + hexlify(iv).upper() + b"0010" + hexlify(ct_cfb64).upper()
    resp_cfb64 = hsm.process_raw_message(req_cfb64)
    assert resp_cfb64 == b"HDR1M300" + hexlify(expected_cfb64_iv).upper() + b"0010" + hexlify(plaintext).upper()

    # 4. OFB (05): Output IV in M3 is the chaining IV
    req_m0_ofb = b"HDR1M0051100B" + key_field + hexlify(iv).upper() + b"1" + b"0010" + hexlify(plaintext).upper()
    resp_m0_ofb = hsm.process_raw_message(req_m0_ofb)
    assert resp_m0_ofb.startswith(b"HDR1M100")
    m0_ofb_iv = resp_m0_ofb[8:24]
    m0_ofb_ct = resp_m0_ofb[28:]
    req_m2_ofb = b"HDR1M2051100B" + key_field + hexlify(iv).upper() + b"1" + b"0010" + m0_ofb_ct
    resp_m2_ofb = hsm.process_raw_message(req_m2_ofb)
    assert resp_m2_ofb == b"HDR1M300" + m0_ofb_iv + b"0010" + hexlify(plaintext).upper()

    # 5. ECB (00): Output IV is omitted in M3
    cipher_ecb = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_ECB)
    ct_ecb = cipher_ecb.encrypt(plaintext)
    req_ecb = b"HDR1M2001100B" + key_field + b"0010" + hexlify(ct_ecb).upper()
    resp_ecb = hsm.process_raw_message(req_ecb)
    assert resp_ecb == b"HDR1M3000010" + hexlify(plaintext).upper()


def test_m2_output_formats_binary_hex_text():
    """Verify M2 supports output format '0' (binary), '1' (hex), '2' (text)."""
    hsm = HSM(header="HDR1")
    clear_key, key_field = _variant_data_key(hsm)
    plaintext = b"SECRET_8"  # 8 ASCII bytes
    cipher = Crypto.Cipher.DES3.new(clear_key + clear_key[:8], Crypto.Cipher.DES3.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    # 1. Output Format '1' (Hex)
    req_hex = b"HDR1M2001100B" + key_field + b"0008" + hexlify(ciphertext).upper()
    resp_hex = hsm.process_raw_message(req_hex)
    assert resp_hex == b"HDR1M3000008" + hexlify(plaintext).upper()

    # 2. Output Format '2' (Text)
    req_txt = b"HDR1M2001200B" + key_field + b"0008" + hexlify(ciphertext).upper()
    resp_txt = hsm.process_raw_message(req_txt)
    assert resp_txt == b"HDR1M3000008" + plaintext

    # 3. Output Format '0' (Binary raw)
    req_bin = b"HDR1M2001000B" + key_field + b"0008" + hexlify(ciphertext).upper()
    resp_bin = hsm.process_raw_message(req_bin)
    assert resp_bin == b"HDR1M3000008" + plaintext


def test_m2_ctr_aes_keyblock_output_iv():
    """Verify M2 in CTR mode ('06') with AES Key Block produces output IV with updated counter."""
    from pythales.crypto.keyblock import TR31KeyBlock

    hsm = HSM(header="HDR1")
    raw_aes_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    hdr = "S0048D0AE00E0000"
    kb_str = TR31KeyBlock.wrap(raw_aes_key, hdr, hsm.LMK).decode("ascii")
    kb_field = "S" + kb_str

    iv = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFB00000001")
    plaintext = b"A" * 32  # 32 bytes = 2 AES blocks
    offset_str = "000"
    length_str = "032"

    # Encrypt with M0
    req_m0 = (
        b"HDR1M00611FFF"
        + kb_field.encode("ascii")
        + hexlify(iv).upper()
        + offset_str.encode("ascii")
        + length_str.encode("ascii")
        + b"0020"
        + hexlify(plaintext).upper()
    )
    resp_m0 = hsm.process_raw_message(req_m0)
    # Per manual, M1 for mode 06 has NO Output IV:
    assert resp_m0.startswith(b"HDR1M1000020")
    ciphertext_hex = resp_m0[12:]

    # Decrypt with M2
    req_m2 = (
        b"HDR1M20611FFF"
        + kb_field.encode("ascii")
        + hexlify(iv).upper()
        + offset_str.encode("ascii")
        + length_str.encode("ascii")
        + b"0020"
        + ciphertext_hex
    )
    resp_m2 = hsm.process_raw_message(req_m2)
    # Per manual, M3 for mode 06 HAS Output IV with counter incremented by 2 blocks!
    # Expected output IV: F0F1F2F3F4F5F6F7F8F9FAFB00000003
    expected_out_iv = "F0F1F2F3F4F5F6F7F8F9FAFB00000003"
    assert resp_m2 == b"HDR1M300" + expected_out_iv.encode("ascii") + b"0020" + hexlify(plaintext).upper()
