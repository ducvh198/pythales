"""
Comprehensive Code-Executing Adversarial Test Suite for Milestone M3 (Pythales).
Designed by teamwork_preview_challenger_m3_2 to stress-test all M3 command pairs:
CA/CB, DC/DD, EC/ED, BA/BB, EE/EF, CW/CX, CY/CZ.
"""

import unittest
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES3
import Crypto.Cipher.AES
from pythales.crypto.tools import get_visa_pvv

from pythales.hsm import HSM
from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block, _decrypt_key
from pythales.commands.card_verify import calculate_cvv, _decrypt_cvk
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header
from pythales.core.errors import ErrorCodes, PayShieldException


class TestMilestoneM3ChallengerAdversarial(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    # -------------------------------------------------------------------------
    # 1. CA / CB: Translate PIN Block (ZPK1 to ZPK2)
    # -------------------------------------------------------------------------

    def test_ca_cb_tr31_scheme_s_keys(self):
        """Stress-test CA/CB using TR-31 Scheme 'S' key blocks for ZPK1 and ZPK2."""
        raw_zpk1 = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        raw_zpk2 = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"

        hdr1 = TR31Header(version_id="S", key_length=80, key_usage="P0", algorithm="T", mode_of_use="E", key_version="00", exportability="E")
        kb1_str = TR31KeyBlock.wrap(raw_zpk1, hdr1, self.hsm.LMK).decode("ascii")

        hdr2 = TR31Header(version_id="S", key_length=80, key_usage="P0", algorithm="T", mode_of_use="E", key_version="00", exportability="E")
        kb2_str = TR31KeyBlock.wrap(raw_zpk2, hdr2, self.hsm.LMK).decode("ascii")

        pan = "4070000000101384"
        pin = "54321"
        pb_src = encrypt_pin_block(raw_zpk1, pin, "01", pan)

        # CA translate from ZPK1 (Scheme S) to ZPK2 (Scheme S)
        ca_req = f"SSSSCA{kb1_str}{kb2_str}12{pb_src}0101{pan}".encode("ascii")
        ca_resp = self.hsm.process_raw_message(ca_req)

        self.assertTrue(ca_resp.startswith(b"SSSSCB00"), f"Expected SSSSCB00, got {ca_resp}")
        dst_pb = ca_resp[8:24].decode("ascii")

        # Decrypt destination PIN block under ZPK2 and verify PIN match
        dec_pin = decrypt_pin_block(raw_zpk2, dst_pb, "01", pan)
        self.assertEqual(dec_pin, pin)

    def test_ca_cb_cross_format_translation_01_to_48_and_back(self):
        """Translate PIN block from Format 0 ('01') to Format 4 ('48') and back."""
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")
        zpk2_bytes = _decrypt_key(self.hsm, zpk2_hex, variant=2)

        pan = "4575272222567122"
        pin = "987654"
        pb_01 = encrypt_pin_block(zpk1_bytes, pin, "01", pan)

        # Translate ZPK1 Format 0 ('01') -> ZPK2 Format 4 ('48')
        ca_req1 = f"SSSSCA{zpk1_hex}{zpk2_hex}12{pb_01}0148{pan}".encode("ascii")
        ca_resp1 = self.hsm.process_raw_message(ca_req1)
        self.assertTrue(ca_resp1.startswith(b"SSSSCB00"))

        pb_48 = ca_resp1[8:40].decode("ascii")
        self.assertEqual(len(pb_48), 32)
        dec_pin_48 = decrypt_pin_block(zpk2_bytes, pb_48, "48", pan)
        self.assertEqual(dec_pin_48, pin)

        # Translate ZPK2 Format 4 ('48') -> ZPK1 Format 0 ('01')
        ca_req2 = f"SSSSCA{zpk2_hex}{zpk1_hex}12{pb_48}4801{pan}".encode("ascii")
        ca_resp2 = self.hsm.process_raw_message(ca_req2)
        self.assertTrue(ca_resp2.startswith(b"SSSSCB00"))

        pb_01_back = ca_resp2[8:24].decode("ascii")
        dec_pin_back = decrypt_pin_block(zpk1_bytes, pb_01_back, "01", pan)
        self.assertEqual(dec_pin_back, pin)

    def test_ca_cb_max_pin_length_checks(self):
        """Verify strict enforcement of max PIN length parameter in CA."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pan = "407000000010"
        pin_6 = "123456"
        pb_6 = encrypt_pin_block(zpk_bytes, pin_6, "01", pan)

        # Max PIN length 5 -> FAIL (CB26)
        ca_bad = f"SSSSCA{zpk_hex}{zpk_hex}05{pb_6}0101{pan}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ca_bad), b"SSSSCB26")

        # Max PIN length 6 -> PASS (CB00)
        ca_good = f"SSSSCA{zpk_hex}{zpk_hex}06{pb_6}0101{pan}".encode("ascii")
        self.assertTrue(self.hsm.process_raw_message(ca_good).startswith(b"SSSSCB00"))

    def test_ca_cb_corrupt_pin_blocks_and_invalid_formats(self):
        """Test CA/CB error handling on corrupted PIN blocks and invalid format codes."""
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")
        pan = "40700000001013843"

        # Format code '02' (unsupported in encrypt/decrypt)
        ca_req_fmt02 = f"SSSSCA{zpk1_hex}{zpk2_hex}12{'0'*16}0202{pan}".encode("ascii")
        ca_resp_fmt02 = self.hsm.process_raw_message(ca_req_fmt02)
        self.assertEqual(ca_resp_fmt02, b"SSSSCB21")

        # Corrupt PIN block header (e.g. Format 0 block starting with 0xF)
        corrupt_block = "F" + "4" + "1234" + "F" * 10
        cipher = Crypto.Cipher.DES3.new(zpk1_bytes, Crypto.Cipher.DES3.MODE_ECB)
        acct_12 = pan[-13:-1] if len(pan) >= 13 else pan.rjust(12, "0")[-12:]
        acct_bytes = unhexlify("0000" + acct_12)
        inter_bytes = bytes(a ^ b for a, b in zip(unhexlify(corrupt_block), acct_bytes))
        enc_corrupt = hexlify(cipher.encrypt(inter_bytes)).decode("ascii").upper()

        ca_req_corrupt = f"SSSSCA{zpk1_hex}{zpk2_hex}12{enc_corrupt}0101{pan}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ca_req_corrupt), b"SSSSCB23")

    # -------------------------------------------------------------------------
    # 2. DC / DD: Verify Customer PIN
    # -------------------------------------------------------------------------

    def test_dc_dd_pvv_verification_success_and_failure(self):
        """Empirical verification of DC/DD for valid and invalid PVV."""
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan = "407000000010"
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")

        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan)

        # Valid PVV -> DD00
        dc_req_valid = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{calc_pvv}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(dc_req_valid), b"SSSSDD00")

        # Invalid PVV -> DD01
        wrong_pvv = "0000" if calc_pvv != "0000" else "9999"
        dc_req_invalid = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{wrong_pvv}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(dc_req_invalid), b"SSSSDD01")

    # -------------------------------------------------------------------------
    # 3. EC / ED: Translate PIN Block under LMK / Verify Interchange PIN
    # -------------------------------------------------------------------------

    def test_ec_ed_translation_under_lmk_mode(self):
        """EC without PVV returns PIN block encrypted under LMK."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        pan = "407000000010"
        pin = "6543"
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)

        # EC request without PVV (just PAN)
        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)

        self.assertTrue(ec_resp.startswith(b"SSSSED00"))
        lmk_pb = ec_resp[8:].decode("ascii")

        # Decrypt lmk_pb using HSM.LMK
        dec_pin = decrypt_pin_block(self.hsm.LMK, lmk_pb, "01", pan)
        self.assertEqual(dec_pin, pin)

    def test_ec_ed_interchange_pvv_verification_mode(self):
        """EC with PVV verifies interchange PIN (ED00 / ED01)."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan = "407000000010"
        pin = "1122"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)

        ec_req_good = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{calc_pvv}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ec_req_good), b"SSSSED00")

        wrong_pvv = "0000" if calc_pvv != "0000" else "1234"
        ec_req_bad = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{wrong_pvv}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ec_req_bad), b"SSSSED01")

    # -------------------------------------------------------------------------
    # 4. BA / BB: Encrypt Clear PIN / Generate Random PIN
    # -------------------------------------------------------------------------

    def test_ba_bb_random_pin_generation(self):
        """BA command random PIN generation modes."""
        # BA empty payload -> 4-digit random PIN
        resp_empty = self.hsm.process_raw_message(b"SSSSBA")
        self.assertTrue(resp_empty.startswith(b"SSSSBB00"))
        pin_empty = resp_empty[8:].decode("ascii")
        self.assertEqual(len(pin_empty), 4)
        self.assertTrue(pin_empty.isdigit())

        # BA length 06 -> 6-digit random PIN
        resp_6 = self.hsm.process_raw_message(b"SSSSBA06")
        self.assertTrue(resp_6.startswith(b"SSSSBB00"))
        pin_6 = resp_6[8:].decode("ascii")
        self.assertEqual(len(pin_6), 6)
        self.assertTrue(pin_6.isdigit())

        # BA invalid length 03 -> Error BB26
        resp_3 = self.hsm.process_raw_message(b"SSSSBA03")
        self.assertEqual(resp_3, b"SSSSBB26")

    def test_ba_bb_encrypt_clear_pin_under_zpk(self):
        """BA encrypt clear PIN under ZPK returns clear PIN + encrypted PIN block."""
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pan = "407000000010"
        clear_pin = "8765"

        ba_req = f"SSSSBA{zpk_hex}{pan}{clear_pin}".encode("ascii")
        ba_resp = self.hsm.process_raw_message(ba_req)
        self.assertTrue(ba_resp.startswith(b"SSSSBB00"))

        payload = ba_resp[8:].decode("ascii")
        returned_pin = payload[:4]
        returned_pb = payload[4:]

        self.assertEqual(returned_pin, clear_pin)
        self.assertEqual(len(returned_pb), 16)

        # Decrypt returned PIN block and verify
        dec_pin = decrypt_pin_block(zpk_bytes, returned_pb, "01", pan)
        self.assertEqual(dec_pin, clear_pin)

    # -------------------------------------------------------------------------
    # 5. EE / EF: Verify IBM 3624 PIN Offset
    # -------------------------------------------------------------------------

    def test_ee_ef_ibm3624_4digit_pin_offset(self):
        """EE/EF 4-digit offset verification."""
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
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        # Correct offset -> EF00
        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}{offset}{val_data}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ee_req), b"SSSSEF00")

        # Wrong offset -> EF01
        ee_req_bad = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}0000{val_data}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(ee_req_bad), b"SSSSEF01")

    # -------------------------------------------------------------------------
    # 6. CW / CX & CY / CZ: CVV Generation & Verification
    # -------------------------------------------------------------------------

    def test_cw_cy_roundtrip_with_semicolon_and_without(self):
        """CW/CX and CY/CZ round-trip with and without semicolon delimiter."""
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00003U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        pan = "4532012345678901"
        exp = "2711"
        svc = "101"

        # 1. With semicolon delimiter: PAN;YYMMSVC
        cw_req_semi = f"SSSSCW{cvk_hex}{pan};{exp}{svc}".encode("ascii")
        cw_resp_semi = self.hsm.process_raw_message(cw_req_semi)
        self.assertTrue(cw_resp_semi.startswith(b"SSSSCX00"))
        cvv_semi = cw_resp_semi[8:].decode("ascii")
        self.assertEqual(len(cvv_semi), 3)

        cy_req_semi = f"SSSSCY{cvk_hex}{cvv_semi}{pan};{exp}{svc}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(cy_req_semi), b"SSSSCZ00")

        # 2. Without semicolon delimiter (fixed format): PANYYMMSVC
        cw_req_fixed = f"SSSSCW{cvk_hex}{pan}{exp}{svc}".encode("ascii")
        cw_resp_fixed = self.hsm.process_raw_message(cw_req_fixed)
        self.assertTrue(cw_resp_fixed.startswith(b"SSSSCX00"))
        cvv_fixed = cw_resp_fixed[8:].decode("ascii")
        self.assertEqual(cvv_fixed, cvv_semi)

        cy_req_fixed = f"SSSSCY{cvk_hex}{cvv_fixed}{pan}{exp}{svc}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(cy_req_fixed), b"SSSSCZ00")

    def test_cw_cy_tr31_scheme_s_cvk(self):
        """CW/CX and CY/CZ with TR-31 Scheme 'S' CVK key block."""
        raw_cvk = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        hdr = TR31Header(version_id="S", key_length=80, key_usage="C0", algorithm="T", mode_of_use="C", key_version="00", exportability="E")
        cvk_kb = TR31KeyBlock.wrap(raw_cvk, hdr, self.hsm.LMK).decode("ascii")

        pan = "4901234567890123"
        exp = "2806"
        svc = "999"

        cw_req = f"SSSSCW{cvk_kb}{pan};{exp}{svc}".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)
        self.assertTrue(cw_resp.startswith(b"SSSSCX00"))

        cvv = cw_resp[8:].decode("ascii")
        self.assertEqual(len(cvv), 3)

        cy_req = f"SSSSCY{cvk_kb}{cvv}{pan};{exp}{svc}".encode("ascii")
        self.assertEqual(self.hsm.process_raw_message(cy_req), b"SSSSCZ00")


if __name__ == "__main__":
    unittest.main()
