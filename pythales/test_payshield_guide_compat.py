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

    monkeypatch.setattr(builtins, "__import__", import_without_psec)
    module_path = Path(__file__).parent / "crypto" / "keyblock.py"
    spec = importlib.util.spec_from_file_location("_keyblock_without_psec", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.psec_tr31 is None
    with pytest.raises(module.PayShieldException) as exc:
        module._require_psec_tr31()
    assert exc.value.error_code == module.ErrorCodes.INTERNAL_HARDWARE_ERROR
