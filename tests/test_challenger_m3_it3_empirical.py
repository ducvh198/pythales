import unittest
from binascii import unhexlify, hexlify
import Crypto.Cipher.AES
import Crypto.Cipher.DES3
from pythales.crypto.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.commands.pin import _extract_pin_block_and_fmt, encrypt_pin_block, decrypt_pin_block, _decrypt_key
from pythales.core.errors import ErrorCodes, PayShieldException


class TestM3It3EmpiricalChallenge(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    # -------------------------------------------------------------------------
    # Group 1: Format 01 requests with PAN ending in "48", "04", "06"
    # -------------------------------------------------------------------------
    def test_dc_format_01_pan_ending_in_48(self):
        """DC command with Format 01 PIN block and 16-digit PAN ending in '48'."""
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

        calc_pvv = get_visa_pvv(
            pan_ending_48.encode("ascii"),
            pvki.encode("ascii"),
            pin.encode("ascii"),
            pvk_hex_16.encode("ascii")
        ).decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_ending_48)

        # Build DC request: SSSSDC <TPK> <PVK> <PB_01> 01 <PAN> <PVKI> <PVV>
        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_ending_48}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_dc_format_01_pan_ending_in_04(self):
        """DC command with Format 01 PIN block and 16-digit PAN ending in '04'."""
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_ending_04 = "4070000000010104"
        pin = "5678"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(
            pan_ending_04.encode("ascii"),
            pvki.encode("ascii"),
            pin.encode("ascii"),
            pvk_hex_16.encode("ascii")
        ).decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_ending_04)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_ending_04}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_dc_format_01_pan_ending_in_06(self):
        """DC command with Format 01 PIN block and 16-digit PAN ending in '06'."""
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_ending_06 = "4070000000010106"
        pin = "9999"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(
            pan_ending_06.encode("ascii"),
            pvki.encode("ascii"),
            pin.encode("ascii"),
            pvk_hex_16.encode("ascii")
        ).decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_ending_06)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_ending_06}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_ec_format_01_pan_ending_in_48(self):
        """EC command (Visa PVV verify) with Format 01 PIN block and 16-digit PAN ending in '48'."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_48 = "4070000000010148"
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(
            pan_48.encode("ascii"),
            pvki.encode("ascii"),
            pin.encode("ascii"),
            pvk_hex_16.encode("ascii")
        ).decode("ascii")

        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan_48)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan_48}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)
        self.assertEqual(ec_resp, b"SSSSED00")

    def test_ca_format_01_pan_ending_in_48(self):
        """CA command (Translate PIN) with Format 01 PIN block and 16-digit PAN ending in '48'."""
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")

        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)
        zpk2_bytes = _decrypt_key(self.hsm, zpk2_hex, variant=2)

        pan_48 = "4070000000010148"
        pin = "7890"
        pb1_01 = encrypt_pin_block(zpk1_bytes, pin, "01", pan_48)

        ca_req = f"SSSSCA{zpk1_hex}{zpk2_hex}12{pb1_01}0101{pan_48}".encode("ascii")
        ca_resp = self.hsm.process_raw_message(ca_req)
        self.assertTrue(ca_resp.startswith(b"SSSSCB00"))

        dst_pb = ca_resp[8:24].decode("ascii")
        decrypted_pin = decrypt_pin_block(zpk2_bytes, dst_pb, "01", pan_48)
        self.assertEqual(decrypted_pin, pin)

    # -------------------------------------------------------------------------
    # Group 2: EE command with 16-digit PANs and Format 4 ('48') PIN blocks
    # -------------------------------------------------------------------------
    def test_ee_format_48_16_digit_pan_success(self):
        """EE command (IBM 3624 verify offset) with Format 4 ('48') PIN block and 16-digit PAN - matching offset."""
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

    def test_ee_format_48_16_digit_pan_mismatch(self):
        """EE command with Format 4 ('48') PIN block and 16-digit PAN - wrong offset returns EF01."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        pin = "1234"
        pan_16 = "4070000000010100"
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        dec_table = "0123456789012345"
        val_data = "4070000000010000"
        wrong_offset = "0000"  # Deliberately wrong

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{dec_table}{wrong_offset}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF01")

    def test_ee_format_04_16_digit_pan_success(self):
        """EE command with Format 4 ('04') PIN block and 16-digit PAN."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "9876"
        pan_16 = "5123456789012345"
        pb_04 = encrypt_pin_block(zpk_bytes, pin, "04", pan_16)

        dec_table = "0123456789012345"
        val_data = "5123456789010000"

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset_4 = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_04}04{pan_16}{dec_table}{offset_4}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

    def test_ee_format_48_with_semicolon_delimiter(self):
        """EE command with Format 4 ('48') PIN block and semicolon-delimited 16-digit PAN."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "2468"
        pan_16 = "4070000000010199"
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

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_48}48{pan_16};{dec_table}{offset_4}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

    # -------------------------------------------------------------------------
    # Group 3: Adversarial Extraction Edge Cases
    # -------------------------------------------------------------------------
    def test_extract_pin_block_and_fmt_direct_vectors(self):
        """Direct extraction test cases for _extract_pin_block_and_fmt."""
        # 1. Format 01 with 16-digit PAN ending in 48 (offset 32..34 is '48')
        pb16 = "1122334455667788"
        pan16_48 = "4070000000010148"
        rem_01 = pb16 + "01" + pan16_48
        pb, fmt, rest = _extract_pin_block_and_fmt(rem_01)
        self.assertEqual(pb, pb16)
        self.assertEqual(fmt, "01")
        self.assertEqual(rest, pan16_48)

        # 2. Format 4 (32 hex chars) with format '48'
        pb32 = "11223344556677889900AABBCCDDEEFF"
        rem_48 = pb32 + "48" + pan16_48
        pb, fmt, rest = _extract_pin_block_and_fmt(rem_48)
        self.assertEqual(pb, pb32)
        self.assertEqual(fmt, "48")
        self.assertEqual(rest, pan16_48)

        # 3. Format 4 (32 hex chars) where ciphertext has '01' at offset 16..18 but non-digits in 18..30
        pb32_coll = "112233445566778801ABCDEF9900AABB"  # offset 16..18 is '01', offset 18..30 contains ABCDEF
        rem_coll = pb32_coll + "48" + pan16_48
        pb, fmt, rest = _extract_pin_block_and_fmt(rem_coll)
        self.assertEqual(pb, pb32_coll)
        self.assertEqual(fmt, "48")
        self.assertEqual(rest, pan16_48)

        # 4. Format 01 with 12-digit PAN and PVV starting with '48' causing offset 32..34 to be '48'
        rem_01_pvv48 = pb16 + "01" + "407000000101" + "1" + "4812"
        # offset 0..16: pb16 (16)
        # offset 16..18: "01" (2)
        # offset 18..30: "407000000101" (12)
        # offset 30: "1" (1)
        # offset 31..35: "4812" -> offset 32..34 is "81" or if PVV is "0481" offset 32..34 is "48"
        rem_01_pvv48_2 = pb16 + "01" + "407000000101" + "10481"
        pb, fmt, rest = _extract_pin_block_and_fmt(rem_01_pvv48_2)
        self.assertEqual(pb, pb16)
        self.assertEqual(fmt, "01")
        self.assertEqual(rest, "40700000010110481")


if __name__ == "__main__":
    unittest.main()
