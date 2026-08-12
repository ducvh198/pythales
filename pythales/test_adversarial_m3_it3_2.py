"""
Adversarial Stress Test Suite for Milestone M3 (Iteration 3) Command Handlers.
Written by teamwork_preview_challenger_m3_it3_2.
"""

import unittest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
from pynblock.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.commands.pin import encrypt_pin_block, _decrypt_key
from pythales.commands.card_verify import _decrypt_cvk, calculate_cvv


class TestMilestoneM3AdversarialIt3(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    def test_ca_cb_omitted_dst_fmt_with_standard_pan(self):
        """
        CA/CB: When dst_fmt is omitted and PAN starts with digits like '40' (e.g. '407000000010'),
        CAHandler mistakenly treats '40' as dst_fmt and fails with unsupported format error ('21' / '15').
        """
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")

        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk1_bytes, "1234", "01", pan)

        # CA request with dst_fmt omitted (src_fmt="01" followed by PAN="407000000010")
        ca_req = f"SSSSCA{zpk1_hex}{zpk2_hex}12{pb_01}01{pan}".encode("ascii")
        ca_resp = self.hsm.process_raw_message(ca_req)

        # Response should be b'SSSSCB00' + translated_pin_block + '01'
        self.assertTrue(ca_resp.startswith(b"SSSSCB00"), f"CA failed with response {ca_resp} because '40' in PAN was misidentified as dst_fmt")

    def test_ba_bb_16_digit_pan_clear_pin(self):
        """
        BA/BB: When encrypting clear PIN under ZPK with a 16-digit PAN (e.g. '4575272222567122'),
        BAHandler hardcodes account_number = rem[:12], shifting the remaining 4 digits of PAN ('7122')
        into clear_pin ('71221234'), resulting in an invalid 8-digit PIN block and corrupted response.
        """
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")

        pan_16 = "4575272222567122"
        clear_pin = "1234"

        ba_req = f"SSSSBA{zpk_hex}{pan_16}{clear_pin}".encode("ascii")
        ba_resp = self.hsm.process_raw_message(ba_req)

        # Expected: SSSSBB00 + '1234' + [16-hex PIN block]
        # Actual: SSSSBB0071221234... (returns clear_pin='71221234')
        self.assertEqual(ba_resp[:12], b"SSSSBB001234", f"BA returned incorrect clear PIN prefix {ba_resp[:12]} due to 12-digit PAN hardcoding")

    def test_dc_dd_visa_pvv_16_digit_pan_correct_slicing(self):
        """
        DC/DD: Visa PVV verification for 16-digit PANs fails when PVV is calculated according to the Visa spec
        (using full PAN[-12:-1] = 11 rightmost digits excluding check digit) because DCHandler passes account_number[:12],
        causing get_visa_pvv to slice the leftmost 11 digits instead of rightmost 11 digits.
        """
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"  # 16-digit PAN
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        # Correct Visa PVV calculated using full 16-digit PAN
        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_16)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_16}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)

        self.assertEqual(dc_resp, b"SSSSDD00", f"DC failed with response {dc_resp} for standard Visa PVV with 16-digit PAN")

    def test_ec_ed_visa_pvv_16_digit_pan_correct_slicing(self):
        """
        EC/ED: Interchange PVV verification for 16-digit PANs fails when PVV is calculated using full PAN
        because ECHandler passes account_number[:12] to get_visa_pvv.
        """
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
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan_16)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan_16}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)

        self.assertEqual(ec_resp, b"SSSSED00", f"EC failed with response {ec_resp} for standard Visa PVV with 16-digit PAN")

    def test_ee_ef_16_digit_pan_custom_dec_table(self):
        """
        EE/EF: EE verification fails with 16-digit PAN when custom decimalization table (e.g. '9876543210543210')
        is used without ';' delimiter, because EEHandler fails to match '0123456789' and falls back to rem[:12].
        """
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "1234"
        pan_16 = "4575272222567122"
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan_16)

        dec_table = "9876543210543210"
        val_data = pan_16

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan_16}{dec_table}{offset}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)

        self.assertEqual(ee_resp, b"SSSSEF00", f"EE failed with response {ee_resp} for 16-digit PAN with custom decimalization table")

    def test_cw_cx_multiple_semicolons(self):
        """
        CW/CX: CW command fails with error '80' / '15' when payload uses standard format with multiple ';' delimiters
        (e.g. 'PAN;EXP;SVC').
        """
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00402U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        cw_req = f"SSSSCW{cvk_hex}4575272222567122;2512;999".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)

        self.assertTrue(cw_resp.startswith(b"SSSSCX00"), f"CW failed with response {cw_resp} for multi-semicolon payload")

    def test_cy_cz_semicolons_with_cvv_at_end(self):
        """
        CY/CZ: CY command fails when CVV is provided after semicolons (e.g. 'PAN;EXP;SVC;CVV')
        because CYHandler steals the first 3 digits of the PAN as expected_cvv.
        """
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00402U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")
        cvk_bytes = _decrypt_cvk(self.hsm, cvk_hex)

        pan = "4575272222567122"
        exp_date = "2512"
        svc = "999"
        expected_cvv = calculate_cvv(cvk_bytes, pan, exp_date, svc)

        cy_req = f"SSSSCY{cvk_hex}{pan};{exp_date};{svc};{expected_cvv}".encode("ascii")
        cy_resp = self.hsm.process_raw_message(cy_req)

        self.assertEqual(cy_resp, b"SSSSCZ00", f"CY failed with response {cy_resp} for PAN-first semicolon payload")


if __name__ == "__main__":
    unittest.main()
