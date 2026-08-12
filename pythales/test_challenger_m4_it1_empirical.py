"""
Empirical Adversarial Test Suite for M4 Data Protection, MAC & EMV Processing.
Covers:
- M0/M1 & M2/M3 (ECB, CBC, CTR, FF1 FPE modes with 16-hex IVs, 1-char & 2-char modes)
- M4/M5 (Translate Data Block across keys and cipher modes)
- M6/M7 & M8/M9 (ISO 9797 Alg 1, ISO 9797 Alg 3, CMAC MAC Generation & Verification)
- KQ/KR (EMV ARQC Generation, ARQC Verification, ARPC Generation)
- KU/KV (EMV Secure Script Encryption & Decryption)
- KY/KZ (EMV Secure Script MAC / Integrity)
"""

import unittest
from binascii import hexlify, unhexlify

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


class TestChallengerM4It1Empirical(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS")

    # =========================================================================
    # 1. M0/M1 & M2/M3: Data Protection (Encrypt & Decrypt)
    # =========================================================================
    def test_m0_m2_ecb_2char_mode_roundtrip(self):
        """M0/M2 ECB mode ('00') roundtrip encryption and decryption."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "0102030405060708090A0B0C0D0E0F10"
        m0_req = f"SSSSM0{dek_hex}000010{data_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}00{enc_len:04X}{enc_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_ecb_1char_mode_roundtrip(self):
        """M0/M2 ECB mode ('0') 1-char mode roundtrip."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "AABBCCDDEEFF00112233445566778899"
        m0_req = f"SSSSM0{dek_hex}00010{data_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}0{enc_len:04X}{enc_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_cbc_custom_iv_roundtrip(self):
        """M0/M2 CBC mode ('01') with 16-hex custom IV."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "11223344556677889900AABBCCDDEEFF"
        iv_hex = "FEDCBA9876543210"

        m0_req = f"SSSSM0{dek_hex}010010{data_hex}{iv_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}01{enc_len:04X}{enc_hex}{iv_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_cbc_1char_mode_roundtrip(self):
        """M0/M2 CBC mode ('1') 1-char mode roundtrip."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "00112233445566778899AABBCCDDEEFF"
        iv_hex = "0102030405060708"

        m0_req = f"SSSSM0{dek_hex}10010{data_hex}{iv_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}1{enc_len:04X}{enc_hex}{iv_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_ctr_custom_iv_roundtrip(self):
        """M0/M2 CTR mode ('06') with 16-hex custom IV."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "0102030405060708090A0B0C0D0E0F"
        iv_hex = "0011223344556677"

        m0_req = f"SSSSM0{dek_hex}06000F{data_hex}{iv_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}06{enc_len:04X}{enc_hex}{iv_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_ctr_1char_mode_roundtrip(self):
        """M0/M2 CTR mode ('6') 1-char mode roundtrip."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        data_hex = "AABBCCDDEEFF001122334455"
        iv_hex = "8899AABBCCDDEEFF"

        m0_req = f"SSSSM0{dek_hex}6000C{data_hex}{iv_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{dek_hex}6{enc_len:04X}{enc_hex}{iv_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_m2_ff1_fpe_roundtrip(self):
        """M0/M2 FF1 FPE mode ('11') roundtrip on numeric string."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        num_str = "9876543210123456"
        m0_req = f"SSSSM0{dek_hex}110010{num_str}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_str = m0_resp[8:].decode("ascii")
        self.assertEqual(len(enc_str), 16)
        self.assertNotEqual(enc_str, num_str)

        m2_req = f"SSSSM2{dek_hex}110010{enc_str}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), num_str)

    def test_m0_m2_tr31_keyblock(self):
        """M0/M2 data encryption using TR-31 Key Block key ('S...')."""
        clear_dek = b"\x01" * 16
        hdr = TR31Header(
            version_id="S",
            key_length=48,
            key_usage="21",
            algorithm="T",
            mode_of_use="B",
            key_version="00",
            exportability="E"
        )
        kb = TR31KeyBlock.wrap(clear_dek, hdr, self.hsm.LMK).decode("ascii")

        data_hex = "1234567890ABCDEF"
        m0_req = f"SSSSM0{kb}000008{data_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))

        enc_hex = m0_resp[8:].decode("ascii")
        enc_len = len(enc_hex) // 2

        m2_req = f"SSSSM2{kb}00{enc_len:04X}{enc_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m0_invalid_payload_error(self):
        """M0 payload shorter than minimum length returns INVALID_DATA_LENGTH (15)."""
        resp = self.hsm.process_raw_message(b"SSSSM0SHORT")
        self.assertTrue(resp.startswith(b"SSSSM115"))

    # =========================================================================
    # 2. M4/M5: Translate Data Block
    # =========================================================================
    def test_m4_m5_translate_cbc_to_ctr(self):
        """M4/M5 translate data block from DEK1 CBC to DEK2 CTR."""
        gen_dek1 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek1_hex = gen_dek1[8:8+33].decode("ascii")
        gen_dek2 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek2_hex = gen_dek2[8:8+33].decode("ascii")

        data_hex = "00112233445566778899AABBCCDDEEFF"
        src_iv = "1234567890ABCDEF"
        tgt_iv = "FEDCBA9876543210"

        # Encrypt under DEK1 CBC
        m0_req = f"SSSSM0{dek1_hex}010010{data_hex}{src_iv}".encode("ascii")
        enc1_hex = self.hsm.process_raw_message(m0_req)[8:].decode("ascii")
        enc1_len = len(enc1_hex) // 2

        # Translate DEK1 CBC -> DEK2 CTR
        m4_req = f"SSSSM4{dek1_hex}{dek2_hex}0106{enc1_len:04X}{enc1_hex}{src_iv}{tgt_iv}".encode("ascii")
        m4_resp = self.hsm.process_raw_message(m4_req)
        self.assertTrue(m4_resp.startswith(b"SSSSM500"))

        enc2_hex = m4_resp[8:].decode("ascii")
        enc2_len = len(enc2_hex) // 2

        # Decrypt under DEK2 CTR
        m2_req = f"SSSSM2{dek2_hex}06{enc2_len:04X}{enc2_hex}{tgt_iv}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m4_m5_translate_ecb_to_cbc(self):
        """M4/M5 translate data block from DEK1 ECB to DEK2 CBC."""
        gen_dek1 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek1_hex = gen_dek1[8:8+33].decode("ascii")
        gen_dek2 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek2_hex = gen_dek2[8:8+33].decode("ascii")

        data_hex = "11223344556677889900AABBCCDDEEFF"
        tgt_iv = "0102030405060708"

        # Encrypt under DEK1 ECB
        m0_req = f"SSSSM0{dek1_hex}000010{data_hex}".encode("ascii")
        enc1_hex = self.hsm.process_raw_message(m0_req)[8:].decode("ascii")
        enc1_len = len(enc1_hex) // 2

        # Translate DEK1 ECB -> DEK2 CBC
        m4_req = f"SSSSM4{dek1_hex}{dek2_hex}0001{enc1_len:04X}{enc1_hex}0000000000000000{tgt_iv}".encode("ascii")
        m4_resp = self.hsm.process_raw_message(m4_req)
        self.assertTrue(m4_resp.startswith(b"SSSSM500"))

        enc2_hex = m4_resp[8:].decode("ascii")
        enc2_len = len(enc2_hex) // 2

        # Decrypt under DEK2 CBC
        m2_req = f"SSSSM2{dek2_hex}01{enc2_len:04X}{enc2_hex}{tgt_iv}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    # =========================================================================
    # 3. M6/M7 & M8/M9: MAC Generation & Verification
    # =========================================================================
    def test_m6_m8_iso9797_alg1(self):
        """M6/M8 ISO 9797 Alg 1 MAC generation and verification."""
        gen_tak = self.hsm.process_raw_message(b"SSSSA0000AU")
        tak_hex = gen_tak[8:8+33].decode("ascii")

        data_hex = "0102030405060708090A"
        m6_req = f"SSSSM6{tak_hex}00000A{data_hex}".encode("ascii")
        m6_resp = self.hsm.process_raw_message(m6_req)
        self.assertTrue(m6_resp.startswith(b"SSSSM700"))

        mac_hex = m6_resp[8:].decode("ascii")
        self.assertEqual(len(mac_hex), 16)

        m8_req = f"SSSSM8{tak_hex}00000A{mac_hex}{data_hex}".encode("ascii")
        m8_resp = self.hsm.process_raw_message(m8_req)
        self.assertEqual(m8_resp, b"SSSSM900")

    def test_m6_m8_iso9797_alg3(self):
        """M6/M8 ISO 9797 Alg 3 MAC generation and verification."""
        gen_tak = self.hsm.process_raw_message(b"SSSSA0000AU")
        tak_hex = gen_tak[8:8+33].decode("ascii")

        data_hex = "AABBCCDDEEFF00112233"
        m6_req = f"SSSSM6{tak_hex}01000A{data_hex}".encode("ascii")
        m6_resp = self.hsm.process_raw_message(m6_req)
        self.assertTrue(m6_resp.startswith(b"SSSSM700"))

        mac_hex = m6_resp[8:].decode("ascii")
        self.assertEqual(len(mac_hex), 16)

        m8_req = f"SSSSM8{tak_hex}01000A{mac_hex}{data_hex}".encode("ascii")
        m8_resp = self.hsm.process_raw_message(m8_req)
        self.assertEqual(m8_resp, b"SSSSM900")

    def test_m6_m8_cmac(self):
        """M6/M8 CMAC generation and verification."""
        gen_tak = self.hsm.process_raw_message(b"SSSSA0000AU")
        tak_hex = gen_tak[8:8+33].decode("ascii")

        data_hex = "11223344556677889900112233445566"
        m6_req = f"SSSSM6{tak_hex}020010{data_hex}".encode("ascii")
        m6_resp = self.hsm.process_raw_message(m6_req)
        self.assertTrue(m6_resp.startswith(b"SSSSM700"))

        mac_hex = m6_resp[8:].decode("ascii")
        self.assertEqual(len(mac_hex), 16)

        m8_req = f"SSSSM8{tak_hex}020010{mac_hex}{data_hex}".encode("ascii")
        m8_resp = self.hsm.process_raw_message(m8_req)
        self.assertEqual(m8_resp, b"SSSSM900")

    def test_m8_mac_verification_failure_error_10(self):
        """M8 MAC mismatch returns Error Code '10' (KCV_MISMATCH)."""
        gen_tak = self.hsm.process_raw_message(b"SSSSA0000AU")
        tak_hex = gen_tak[8:8+33].decode("ascii")

        data_hex = "0102030405060708"
        bad_mac = "0000000000000000"

        m8_req = f"SSSSM8{tak_hex}000008{bad_mac}{data_hex}".encode("ascii")
        m8_resp = self.hsm.process_raw_message(m8_req)
        self.assertTrue(m8_resp.startswith(b"SSSSM910"))

    # =========================================================================
    # 4. KQ/KR: EMV Processing (ARQC / ARPC)
    # =========================================================================
    def test_kq_kr_mode1_generate_arqc(self):
        """KQ Mode 1: Generate ARQC."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "001A"
        txn_data_hex = "00000000100000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        kq_req = f"SSSSKQ1{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        kq_resp = self.hsm.process_raw_message(kq_req)
        self.assertTrue(kq_resp.startswith(b"SSSSKR00"))

        arqc_hex = kq_resp[8:].decode("ascii")
        self.assertEqual(len(arqc_hex), 16)

    def test_kq_kr_mode0_verify_arqc_and_generate_arpc(self):
        """KQ Mode 0: Verify ARQC and Generate ARPC."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "001B"
        txn_data_hex = "00000000200000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        # Step 1: Generate ARQC via KQ1
        kq1_req = f"SSSSKQ1{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        arqc_hex = self.hsm.process_raw_message(kq1_req)[8:].decode("ascii")

        # Step 2: Verify ARQC and generate ARPC via KQ0
        arc_hex = "3030"
        kq0_req = f"SSSSKQ0{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{arqc_hex}{arc_hex}".encode("ascii")
        kq0_resp = self.hsm.process_raw_message(kq0_req)
        self.assertTrue(kq0_resp.startswith(b"SSSSKR00"))

        arpc_hex = kq0_resp[8:].decode("ascii")
        self.assertEqual(len(arpc_hex), 16)

    def test_kq_kr_mode2_verify_arqc_only(self):
        """KQ Mode 2: Verify ARQC only."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "001C"
        txn_data_hex = "00000000300000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        # Step 1: Generate ARQC via KQ1
        kq1_req = f"SSSSKQ1{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        arqc_hex = self.hsm.process_raw_message(kq1_req)[8:].decode("ascii")

        # Step 2: Verify ARQC via KQ2
        kq2_req = f"SSSSKQ2{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{arqc_hex}".encode("ascii")
        kq2_resp = self.hsm.process_raw_message(kq2_req)
        self.assertEqual(kq2_resp, b"SSSSKR00")

    def test_kq_kr_fixed_16digit_pan(self):
        """KQ command with fixed 16-digit PAN (without semicolon delimiter)."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "001E"
        txn_data_hex = "00000000400000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        kq_req = f"SSSSKQ1{mdk_hex}{pan}{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        kq_resp = self.hsm.process_raw_message(kq_req)
        self.assertTrue(kq_resp.startswith(b"SSSSKR00"))

    def test_kq_kr_arqc_mismatch_error_29(self):
        """KQ ARQC verification failure returns Error Code '29' (PIN_VERIFICATION_FAILED)."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "001D"
        txn_data_hex = "0000000010000000000000000840"
        txn_len = len(txn_data_hex) // 2
        bad_arqc = "1122334455667788"

        kq_req = f"SSSSKQ2{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{bad_arqc}".encode("ascii")
        kq_resp = self.hsm.process_raw_message(kq_req)
        self.assertTrue(kq_resp.startswith(b"SSSSKR29"))

    # =========================================================================
    # 5. KU/KV & KY/KZ: EMV Secure Scripting
    # =========================================================================
    def test_ku_kv_script_encryption_roundtrip(self):
        """KU/KV EMV script encryption and decryption roundtrip."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        atc_hex = "000F"
        script_hex = "84240000081122334455667788"
        script_len = len(script_hex) // 2

        # KU Encrypt Script
        ku_req = f"SSSSKU{mdk_hex}{atc_hex}{script_len:04X}{script_hex}".encode("ascii")
        ku_resp = self.hsm.process_raw_message(ku_req)
        self.assertTrue(ku_resp.startswith(b"SSSSKV00"))

        enc_script_hex = ku_resp[8:].decode("ascii")
        enc_len = len(enc_script_hex) // 2

        # KV Decrypt Script
        kv_req = f"SSSSKV{mdk_hex}{atc_hex}{enc_len:04X}{enc_script_hex}".encode("ascii")
        kv_resp = self.hsm.process_raw_message(kv_req)
        self.assertTrue(kv_resp.startswith(b"SSSSKW00") or kv_resp.startswith(b"SSSSKV00"))

        dec_script_hex = kv_resp[8:].decode("ascii")
        self.assertEqual(dec_script_hex, script_hex)

    def test_ky_kz_script_integrity_mac(self):
        """KY/KZ EMV script MAC generation."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        atc_hex = "001E"
        script_hex = "841800000411223344"
        script_len = len(script_hex) // 2

        ky_req = f"SSSSKY{mdk_hex}{atc_hex}{script_len:04X}{script_hex}".encode("ascii")
        ky_resp = self.hsm.process_raw_message(ky_req)
        self.assertTrue(ky_resp.startswith(b"SSSSKZ00"))

        mac_hex = ky_resp[8:].decode("ascii")
        self.assertEqual(len(mac_hex), 16)


if __name__ == "__main__":
    unittest.main()
