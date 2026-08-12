"""
Targeted Empirical Stress Test for M3 Implementation Flaws in Pythales.
Written by teamwork_preview_challenger_m3_2.
"""

import unittest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
from pynblock.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block, _decrypt_key


class TestMilestoneM3Flaws(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    def test_flaw1_dc_dd_format_48_pan_16_digits_fails(self):
        """
        FLAW 1: DC/DD fails for Format 4 ('48') PIN blocks with 16-digit PANs
        because DCHandler hardcodes account_number = rem[:12].
        """
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"  # Standard 16-digit PAN
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        # Calculate PVV for 16-digit PAN
        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")

        # Encrypt PIN block using Format 4 ('48') and 16-digit PAN
        pb_48 = encrypt_pin_block(tpk_bytes, pin, "48", pan_16)

        # Send DC request with 16-digit PAN
        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)

        # Expected: SSSSDD00 (PVV Verification Success)
        # Actual: SSSSDD01 (Failed because DCHandler truncated PAN to 12 digits, breaking Format 4 Block 2)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_flaw2_ec_ed_format_48_pan_16_digits_fails(self):
        """
        FLAW 2: EC/ED interchange PVV verification fails for Format 4 ('48') with 16-digit PANs
        because ECHandler hardcodes account_number = rem[:18] for Format 4.
        """
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"  # 16-digit PAN
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)

        # Expected: SSSSED00
        # Actual: SSSSED01
        self.assertEqual(ec_resp, b"SSSSED00")

    def test_flaw3_ee_ef_6digit_pin_offset_fails(self):
        """
        FLAW 3: EE/EF fails for 6-digit PIN offsets because EEHandler hardcodes offset = rem[:4].
        """
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "123456"  # 6-digit PIN
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

        # Expected: SSSSEF00
        # Actual: SSSSEF01 (because offset was sliced as rem[:4] instead of rem[:6])
        self.assertEqual(ee_resp, b"SSSSEF00")

    def test_flaw4_fmt01_rem_32_34_collision_misidentified_as_format4(self):
        """
        FLAW 4: Format 01 (DES) requests are misidentified as Format 4 (AES) whenever
        indices 32..33 of remaining payload `rem` happen to be '04' or '48'.
        This causes _extract_pin_block_and_fmt to extract 32 hex chars as a Format 4
        PIN block, crashing DC/EC/EE commands with error code '23' (INVALID_PIN_BLOCK).
        """
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)
        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, "1234", "01", "407000000010")

        # Payload: 16 hex pinblock + '01' format + 12 digit PAN + 1 digit PVKI + 4 digit PVV ('3049')
        # Total rem length = 35. rem[32:34] is '04'.
        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}0140700000001013049".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)

        # Expected: b'SSSSDD01' (or 'DD00'), NOT 'DD23' (INVALID_PIN_BLOCK due to Format 4 misidentification)
        self.assertIn(dc_resp, (b"SSSSDD01", b"SSSSDD00"), f"DC failed with response {dc_resp} because Format 01 request with '04' at rem[32:34] was misidentified as Format 4")


if __name__ == "__main__":
    unittest.main()

