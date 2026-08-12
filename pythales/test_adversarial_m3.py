"""
Adversarial and Edge-Case Test Suite for Milestone M3 (PIN Processing & Card Verification).
"""

import unittest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
from pynblock.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block, _decrypt_key
from pythales.core.errors import ErrorCodes, PayShieldException


class TestMilestoneM3Adversarial(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    def test_ca_cb_pin_length_overflow_and_invalid_formats(self):
        # Generate ZPK1 and ZPK2
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")

        pan = "407000000010"
        # 6-digit PIN
        pin = "123456"
        pb_01 = encrypt_pin_block(zpk1_bytes, pin, "01", pan)

        # Max PIN length set to 04 -> Should fail with '26' (PIN length out of range)
        ca_req_overflow = f"SSSSCA{zpk1_hex}{zpk2_hex}04{pb_01}0101{pan}".encode("ascii")
        ca_resp_overflow = self.hsm.process_raw_message(ca_req_overflow)
        self.assertEqual(ca_resp_overflow, b"SSSSCB26")

    def test_format_48_aes_and_3des_pin_block_roundtrip(self):
        key16 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        pan = "4575272222567122"

        for pin in ("1234", "123456", "987654321012"):
            enc_pb = encrypt_pin_block(key16, pin, "48", pan)
            self.assertEqual(len(enc_pb), 32)
            dec_pin = decrypt_pin_block(key16, enc_pb, "48", pan)
            self.assertEqual(dec_pin, pin)

    def test_format_01_pin_block_roundtrip(self):
        key16 = b"\x11" * 16
        pan = "40700000001013843"

        for pin in ("1111", "9999", "12345678"):
            enc_pb = encrypt_pin_block(key16, pin, "01", pan)
            self.assertEqual(len(enc_pb), 16)
            dec_pin = decrypt_pin_block(key16, enc_pb, "01", pan)
            self.assertEqual(dec_pin, pin)

    def test_dc_dd_pvk_variant3_and_mismatch_verification(self):
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        pan = "407000000010"
        pin = "1234"
        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan)

        # Send invalid PVV -> Returns DD01
        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan}10000".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD01")

    def test_ee_ef_ibm3624_mismatch_and_verification(self):
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "9876"
        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)

        dec_table = "0123456789012345"
        val_data = "4070000000100000"

        val_bytes = unhexlify(val_data)
        cipher = Crypto.Cipher.DES3.new(pvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        # Correct offset -> EF00
        ee_good = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}{offset}{val_data}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ee_good), b"SSSSEF00")

        # Wrong offset -> EF01
        ee_bad = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}0000{val_data}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ee_bad), b"SSSSEF01")

    def test_cw_cy_delimiter_parsing_and_cvv_verification(self):
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00003U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        # CW with semicolon
        cw_req = f"SSSSCW{cvk_hex}4000123456789010;2512101".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)
        self.assertTrue(cw_resp.startswith(b"SSSSCX00"))
        cvv = cw_resp[8:].decode("ascii")
        self.assertEqual(len(cvv), 3)

        # CY with semicolon matching
        cy_req = f"SSSSCY{cvk_hex}{cvv}4000123456789010;2512101".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(cy_req), b"SSSSCZ00")

        # CY with semicolon mismatch
        cy_bad = f"SSSSCY{cvk_hex}9994000123456789010;2512101".encode("ascii") if cvv != "999" else f"SSSSCY{cvk_hex}8884000123456789010;2512101".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(cy_bad), b"SSSSCZ01")

    def test_format_48_iso_vector_aes128(self):
        key16 = b"\x01" * 16
        pan = "4575272222567122"
        pin = "1234"
        expected_cipher = "F480606AA7AF374FDC1947194E91B6BD"

        enc_pb = encrypt_pin_block(key16, pin, "48", pan)
        self.assertEqual(enc_pb, expected_cipher)
        dec_pin = decrypt_pin_block(key16, expected_cipher, "48", pan)
        self.assertEqual(dec_pin, pin)

    def test_dc_dd_format_48_16_digit_pan(self):
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_48 = encrypt_pin_block(tpk_bytes, pin, "48", pan_16)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_ec_ed_format_48_16_digit_pan(self):
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)
        self.assertEqual(ec_resp, b"SSSSED00")

    def test_ee_ef_6digit_pin_offset(self):
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "123456"
        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)

        dec_table = "0123456789012345"
        val_data = "4070000000100000"

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:6]
        offset_6 = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(6)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}{offset_6}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

    def test_invalid_pin_block_format_99_returns_error_21(self):
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}00000000000000009940700000001010000".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD21")

    def test_fmt01_pan_pvv_collision_04_48_parsed_as_fmt01(self):
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_ending_48 = "4070000000010148"
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_ending_48.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_ending_48)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_ending_48}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_ee_ef_format_48_16_digit_pan(self):
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "1234"
        pan_16 = "4070000000010100"
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        dec_table = "0123456789012345"
        val_data = "4070000000010000"

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset_4 = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{dec_table}{offset_4}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")


if __name__ == "__main__":
    unittest.main()

