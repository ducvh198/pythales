"""NIST SP 800-38G FF1 known-answer tests."""

from binascii import unhexlify

import pytest

from pythales.commands.mac_data import FF1Cipher


@pytest.mark.parametrize(
    ("tweak_hex", "ciphertext"),
    [
        ("", "2433477484"),
        ("39383736353433323130", "6124200773"),
    ],
)
def test_ff1_aes128_nist_sample_vectors(tweak_hex, ciphertext):
    cipher = FF1Cipher(
        unhexlify("2B7E151628AED2A6ABF7158809CF4F3C"),
        radix=10,
        tweak=unhexlify(tweak_hex),
    )

    assert cipher.encrypt("0123456789") == ciphertext
    assert cipher.decrypt(ciphertext) == "0123456789"


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_ff1_accepts_all_aes_key_sizes(key_size):
    cipher = FF1Cipher(bytes(range(key_size)), radix=10)
    plaintext = "0123456789"

    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext


def test_ff1_rejects_non_aes_key_size():
    with pytest.raises(ValueError, match="AES key"):
        FF1Cipher(b"not-an-aes-key")
