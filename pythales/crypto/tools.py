"""Small payment-crypto helpers used by the legacy command implementation.

These helpers replace the unmaintained ``pynblock`` dependency, which depends
on the obsolete and incompatible ``pycrypto`` package.
"""

from binascii import hexlify, unhexlify

from Crypto.Cipher import DES, DES3


def str2bytes(data):
    return data.encode("utf-8")


def raw2str(raw_data):
    return hexlify(raw_data).decode("ascii").upper()


def raw2B(raw_data):
    return raw2str(raw_data).encode("ascii")


def B2raw(bin_data):
    return unhexlify(bin_data)


def xor(block1, block2):
    left = B2raw(block1)
    right = B2raw(block2)
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return raw2B(bytes(a ^ b for a, b in zip(left, right)))


def key_CV(key, kcv_length=6):
    clear_key = B2raw(key)
    cipher = DES3.new(clear_key, DES3.MODE_ECB)
    return raw2B(cipher.encrypt(b"\x00" * 8))[:kcv_length]


def get_digits_from_string(ciphertext, length=4):
    digits = "".join(char for char in ciphertext if char.isdecimal())[:length]
    if len(digits) < length:
        for char in ciphertext:
            value = int(char, 16)
            if value >= 10:
                digits += str(value - 10)
                if len(digits) == length:
                    break
    return digits


def get_visa_pvv(account_number, key_index, pin, PVK):
    tsp = account_number[-12:-1] + key_index + pin
    if len(PVK) != 32:
        raise ValueError("Incorrect key length")

    # Preserve the historical pynblock contract: each half is supplied as a
    # 16-byte value directly to 2-key TDES, while the TSP is hex-decoded.
    left = DES3.new(PVK[:16], DES3.MODE_ECB)
    right = DES3.new(PVK[16:], DES3.MODE_ECB)
    encrypted_tsp = left.encrypt(right.decrypt(left.encrypt(B2raw(tsp))))
    return get_digits_from_string(raw2str(encrypted_tsp)).encode("ascii")


def get_visa_cvv(account_number, exp_date, service_code, CVK):
    if len(CVK) != 32:
        raise ValueError("Incorrect key length")

    tsp = exp_date + service_code + b"000000000"
    key = B2raw(CVK)
    block1 = DES.new(key[:8], DES.MODE_ECB).encrypt(B2raw(account_number))
    block2 = DES3.new(key, DES3.MODE_ECB).encrypt(B2raw(xor(raw2B(block1), tsp)))
    return get_digits_from_string(raw2str(block2), 3)


def get_clear_pin(pinblock, account_number):
    raw_pinblock = B2raw(pinblock)
    raw_account = B2raw(b"0000" + account_number)
    pin_field = raw2str(bytes(a ^ b for a, b in zip(raw_pinblock, raw_account)))
    pin_length = int(pin_field[:2], 16)
    if not 4 <= pin_length <= 8:
        raise ValueError(f"Incorrect PIN length: {pin_length}")
    pin = pin_field[2:2 + pin_length]
    if not pin.isdecimal():
        raise ValueError("PIN contains non-numeric characters")
    return pin.encode("ascii")


def check_key_parity(key):
    """Return whether every DES key byte has odd parity."""
    return all(byte.bit_count() % 2 == 1 for byte in key)


def modify_key_parity(key):
    """Set the least-significant bit of every DES key byte for odd parity."""
    return bytes(
        byte if byte.bit_count() % 2 == 1 else byte ^ 0x01
        for byte in key
    )
