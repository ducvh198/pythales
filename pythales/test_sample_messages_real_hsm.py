"""
Test suite validating the 7 real HSM message structures:
1. CVK (under LMK): A01FFFS#C0T2C00E00 -> A100S10096C0TC00E0000... + 6-char KCV
2. GEN CVC: CWS10096...;3112000\\x19 -> CX00... (no trailing delimiter)
3. VERIFY CVC: CYS10096...<cvv><pan>;<exp><svc> -> CZ00
4. HMAC KEY (under LMK): L0FFFF003204#63H0C00E00 -> L100FFFF1012863HC00E0000...
5. GEN HMAC: LQFF003204FFFF<HMAC_KEY>000100123456789 -> LR000032<32 bytes binary HMAC>
6. VERIFY HMAC: LSFF0032<binary_hmac>04FFFF<HMAC_KEY>000100123456789\\x19 -> LT00
7. DEK (under LMK): A00FFFS#21A3B00E00 -> A100S1012821AB00E0000... + 6-char KCV
"""

import unittest
from binascii import unhexlify, hexlify

from pythales.hsm import PyThalesHSM
from pythales.core.errors import ErrorCodes
from pythales.commands.key_mgmt import _extract_key_string
from pythales.crypto.keyblock import TR31KeyBlock


class TestRealHSMSampleMessages(unittest.TestCase):
    def setUp(self):
        self.hsm = PyThalesHSM(header=b"0000")
        self.header = b"0000"

    def make_request(self, command_code: bytes, payload: bytes) -> bytes:
        return self.header + command_code + payload

    def test_1_cvk_generation_under_lmk(self):
        """
        1. CVK (under LMK):
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000A01FFFS#C0T2C00E00" -L -D
        <<< A100S10096C0TC00E000038891BF63C6556E3C7B3A9835E4CDEBFAB75E59224B77223E8D5D030FDED798BC97A876A124F00026183C7
        """
        raw_req = self.make_request(b"A0", b"1FFFS#C0T2C00E00")
        resp = self.hsm.process_raw_message(raw_req, header_length=4)

        # Header echo: "0000"
        self.assertTrue(resp.startswith(b"0000A100S10096C0TC00E0000"))
        # Total response length: 4 (hdr) + 2 (A1) + 2 (00) + 1 (S) + 96 (KB) + 6 (KCV) = 111 bytes
        self.assertEqual(len(resp), 111)

        payload = resp[4:]  # strip header
        resp_code = payload[:2].decode("ascii")
        err_code = payload[2:4].decode("ascii")
        key_and_kcv = payload[4:].decode("ascii")

        self.assertEqual(resp_code, "A1")
        self.assertEqual(err_code, ErrorCodes.SUCCESS)

        key_str, rem_kcv = _extract_key_string(key_and_kcv)
        self.assertEqual(len(key_str), 97)  # 'S' + 96 chars key block
        self.assertTrue(key_str.startswith("S10096C0TC00E0000"))
        self.assertEqual(len(rem_kcv), 6)  # 6 hex chars KCV

        # Verify key block can be unwrapped cleanly
        hdr, clear_cvk = TR31KeyBlock.unwrap(key_str, self.hsm.LMK)
        self.assertEqual(hdr.key_usage, "C0")
        self.assertEqual(hdr.algorithm, "T")
        self.assertEqual(hdr.mode_of_use, "C")
        self.assertEqual(hdr.version_id, "1")
        self.assertEqual(len(clear_cvk), 16)

    def test_2_and_3_gen_and_verify_cvc(self):
        """
        2. GEN CVC:
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000CWS10096C0TC00E000038891...00029704110000000001;3112000\\x19" -L -D
        <<< CX00833

        3. VERIFY CVC:
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000CYS10096C0TC00E000038891...00028339704110000000001;3112000" -L -D
        <<< CZ00
        """
        # Step 1: Generate CVK
        cvk_req = self.make_request(b"A0", b"1FFFS#C0T2C00E00")
        cvk_resp = self.hsm.process_raw_message(cvk_req, header_length=4)
        cvk_str, _ = _extract_key_string(cvk_resp[8:].decode("ascii"))

        # Step 2: Generate CVC
        pan = "9704110000000001"
        exp = "3112"
        svc = "000"
        cw_payload = f"{cvk_str}{pan};{exp}{svc}\x19".encode("ascii")
        cw_req = self.make_request(b"CW", cw_payload)
        cw_resp = self.hsm.process_raw_message(cw_req, header_length=4)

        # Expected: Header "0000" + "CX" + "00" + 3-digit CVV (NO trailing \x19!)
        self.assertEqual(len(cw_resp), 11)  # 4 + 2 + 2 + 3 = 11
        self.assertTrue(cw_resp.startswith(b"0000CX00"))
        cvv = cw_resp[8:].decode("ascii")
        self.assertEqual(len(cvv), 3)
        self.assertTrue(cvv.isdigit())

        # Step 3: Verify CVC (format: CVK + CVV + PAN + ';' + EXP + SVC)
        cy_payload = f"{cvk_str}{cvv}{pan};{exp}{svc}".encode("ascii")
        cy_req = self.make_request(b"CY", cy_payload)
        cy_resp = self.hsm.process_raw_message(cy_req, header_length=4)

        self.assertEqual(cy_resp, b"0000CZ00")

        # Step 4: Verify CVC failure on wrong CVV
        wrong_cvv = "999" if cvv != "999" else "000"
        cy_bad_payload = f"{cvk_str}{wrong_cvv}{pan};{exp}{svc}".encode("ascii")
        cy_bad_resp = self.hsm.process_raw_message(self.make_request(b"CY", cy_bad_payload), header_length=4)
        self.assertEqual(cy_bad_resp, b"0000CZ01")

    def test_4_hmac_key_generation_under_lmk(self):
        """
        4. HMAC KEY (under LMK):
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000L0FFFF003204#63H0C00E00" -L -D
        <<< L100FFFF1012863HC00E00008923620F3090132409C88FB9EEFCFFC9251C1D2F1C818895B3E28B35616857A54B3A5B0D7AFF3F63BEDA8A724412002E8248102CFF908D00
        """
        raw_req = self.make_request(b"L0", b"FFFF003204#63H0C00E00")
        resp = self.hsm.process_raw_message(raw_req, header_length=4)

        # Expected: Header "0000" + "L1" + "00" + "FFFF" + 128-char Key Block (starts with "1012863HC00E0000")
        self.assertEqual(len(resp), 4 + 2 + 2 + 4 + 128)  # 140 bytes
        self.assertTrue(resp.startswith(b"0000L100FFFF1012863HC00E0000"))

        key_block_str = resp[12:].decode("ascii")
        self.assertEqual(len(key_block_str), 128)

        # Verify key block can be unwrapped
        hdr, clear_hmac_key = TR31KeyBlock.unwrap(key_block_str, self.hsm.LMK)
        self.assertEqual(hdr.key_usage, "63")
        self.assertEqual(hdr.algorithm, "H")
        self.assertEqual(hdr.mode_of_use, "C")
        self.assertEqual(hdr.version_id, "1")
        self.assertEqual(len(clear_hmac_key), 32)

    def test_5_and_6_gen_and_verify_hmac(self):
        """
        5. GEN HMAC:
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000LQFF003204FFFF<HMAC_KEY>000100123456789" -L -D
        <<< LR000032<32 bytes binary HMAC>

        6. VERIFY HMAC:
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000LSFF0032<32 bytes binary HMAC>04FFFF<HMAC_KEY>000100123456789\\x19" -L -D
        <<< LT00
        """
        # Step 1: Generate HMAC key
        l0_req = self.make_request(b"L0", b"FFFF003204#63H0C00E00")
        l0_resp = self.hsm.process_raw_message(l0_req, header_length=4)
        hmac_key_str = l0_resp[12:].decode("ascii")

        # Step 2: Generate HMAC
        data_to_mac = b"0123456789"
        data_len_str = f"{len(data_to_mac):05d}"
        lq_payload = f"FF003204FFFF{hmac_key_str}{data_len_str}".encode("ascii") + data_to_mac
        lq_req = self.make_request(b"LQ", lq_payload)
        lq_resp = self.hsm.process_raw_message(lq_req, header_length=4)

        # Response: 4 (header) + 2 (LR) + 2 (00) + 4 (0032) + 32 (binary HMAC) = 44 bytes
        self.assertEqual(len(lq_resp), 44)
        self.assertTrue(lq_resp.startswith(b"0000LR000032"))
        hmac_bytes = lq_resp[12:]
        self.assertEqual(len(hmac_bytes), 32)

        # Step 3: Verify HMAC (LS command)
        # LS Payload: FF (2) + 0032 (4) + hmac_bytes (32) + 04 (2) + FFFF (4) + hmac_key_str (128) + data_len (5) + data (10) + \x19
        ls_payload = (
            b"FF0032"
            + hmac_bytes
            + f"04FFFF{hmac_key_str}{data_len_str}".encode("ascii")
            + data_to_mac
            + b"\x19"
        )
        ls_req = self.make_request(b"LS", ls_payload)
        ls_resp = self.hsm.process_raw_message(ls_req, header_length=4)

        self.assertEqual(ls_resp, b"0000LT00")

        # Step 4: Verify HMAC failure on tampered message
        ls_bad_payload = (
            b"FF0032"
            + hmac_bytes
            + f"04FFFF{hmac_key_str}{data_len_str}".encode("ascii")
            + b"TAMPERED!!"
            + b"\x19"
        )
        ls_bad_resp = self.hsm.process_raw_message(self.make_request(b"LS", ls_bad_payload), header_length=4)
        self.assertEqual(ls_bad_resp, b"0000LT01")

    def test_7_dek_generation_under_lmk(self):
        """
        7. DEK (under LMK):
        >>> ./tcp-client 10.2.254.41 -p 10098 -a "0000A00FFFS#21A3B00E00" -L -D
        <<< A100S1012821AB00E000091788242...7E160F
        """
        raw_req = self.make_request(b"A0", b"0FFFS#21A3B00E00")
        resp = self.hsm.process_raw_message(raw_req, header_length=4)

        # Expected: Header "0000" + "A1" + "00" + "S1012821AB00E0000..." (129 chars) + 6 chars KCV
        # Total length: 4 + 2 + 2 + 1 + 128 + 6 = 143 bytes
        self.assertEqual(len(resp), 143)
        self.assertTrue(resp.startswith(b"0000A100S1012821AB00E0000"))

        payload = resp[4:]
        key_and_kcv = payload[4:].decode("ascii")
        key_str, rem_kcv = _extract_key_string(key_and_kcv)
        self.assertEqual(len(key_str), 129)  # 'S' + 128 chars key block
        self.assertEqual(len(rem_kcv), 6)

        hdr, clear_dek = TR31KeyBlock.unwrap(key_str, self.hsm.LMK)
        self.assertEqual(hdr.key_usage, "21")
        self.assertEqual(hdr.algorithm, "A")
        self.assertEqual(hdr.mode_of_use, "B")
        self.assertEqual(hdr.version_id, "1")
        self.assertEqual(len(clear_dek), 32)  # 256 bits = 32 bytes

    def test_8_dek_keyblock_m0_m2_roundtrip_standard_wire_format(self):
        """
        8. Test M0 (Encrypt Data Block) & M2 (Decrypt Data Block) using Key Block DEK (AES-256):
        Standard payShield 10K wire format:
        M0: Mode '00' (ECB) + InFmt '1' (Hex) + OutFmt '1' (Hex) + KeyType 'FFF' + DEK KeyBlock + MsgLen '0010' + Msg (32 hex)
        M1 response: 'M1' + '00' + '0010' + Ciphertext (32 hex)
        M2: Mode '00' (ECB) + InFmt '1' (Hex) + OutFmt '1' (Hex) + KeyType 'FFF' + DEK KeyBlock + MsgLen '0010' + Ciphertext (32 hex)
        M3 response: 'M3' + '00' + '0010' + Plaintext (32 hex)
        """
        # Step 1: Generate AES-256 DEK under LMK Key Block
        a0_req = self.make_request(b"A0", b"0FFFS#21A3B00E00")
        a0_resp = self.hsm.process_raw_message(a0_req, header_length=4)
        dek_str, _ = _extract_key_string(a0_resp[8:].decode("ascii"))

        # Test 8a: ECB Mode (00)
        plaintext_hex = "00112233445566778899AABBCCDDEEFF"
        msg_len_hex = f"{len(plaintext_hex) // 2:04X}"  # '0010' (16 bytes)

        m0_payload = f"0011FFF{dek_str}{msg_len_hex}{plaintext_hex}".encode("ascii")
        m0_req = self.make_request(b"M0", m0_payload)
        m0_resp = self.hsm.process_raw_message(m0_req, header_length=4)

        # Expected: Header "0000" + "M1" + "00" + "0010" + Ciphertext (32 hex)
        self.assertTrue(m0_resp.startswith(b"0000M100" + msg_len_hex.encode("ascii")))
        ciphertext_hex = m0_resp[12:].decode("ascii")
        self.assertEqual(len(ciphertext_hex), 32)
        self.assertNotEqual(ciphertext_hex, plaintext_hex)

        # M2 Decrypt
        m2_payload = f"0011FFF{dek_str}{msg_len_hex}{ciphertext_hex}".encode("ascii")
        m2_req = self.make_request(b"M2", m2_payload)
        m2_resp = self.hsm.process_raw_message(m2_req, header_length=4)

        self.assertEqual(m2_resp, b"0000M300" + msg_len_hex.encode("ascii") + plaintext_hex.encode("ascii"))

        # Test 8b: CBC Mode (01) with 32-hex-char IV
        iv_hex = "0102030405060708090A0B0C0D0E0F10"  # 32 hex chars = 16 bytes
        m0_cbc_payload = f"0111FFF{dek_str}{iv_hex}{msg_len_hex}{plaintext_hex}".encode("ascii")
        m0_cbc_req = self.make_request(b"M0", m0_cbc_payload)
        m0_cbc_resp = self.hsm.process_raw_message(m0_cbc_req, header_length=4)

        # M1 CBC Response: Header "0000" + "M1" + "00" + Output_IV (32 hex) + MsgLen (0010) + Ciphertext (32 hex)
        self.assertEqual(len(m0_cbc_resp), 4 + 2 + 2 + 32 + 4 + 32)
        self.assertTrue(m0_cbc_resp.startswith(b"0000M100"))
        output_iv_hex = m0_cbc_resp[8:40].decode("ascii")
        cbc_ciphertext_hex = m0_cbc_resp[44:].decode("ascii")
        self.assertNotEqual(cbc_ciphertext_hex, plaintext_hex)

        # M2 CBC Decrypt
        m2_cbc_payload = f"0111FFF{dek_str}{iv_hex}{msg_len_hex}{cbc_ciphertext_hex}".encode("ascii")
        m2_cbc_req = self.make_request(b"M2", m2_cbc_payload)
        m2_cbc_resp = self.hsm.process_raw_message(m2_cbc_req, header_length=4)

        self.assertEqual(m2_cbc_resp, b"0000M300" + output_iv_hex.encode("ascii") + msg_len_hex.encode("ascii") + plaintext_hex.encode("ascii"))

    def test_9_dek_3des_keyblock_m0_m2_roundtrip(self):
        """
        9. Test M0 & M2 using 3DES DEK under Key Block (TR-31 Version 1, Key Usage '21', Algorithm 'T'):
        """
        # Step 1: Generate 3DES DEK under LMK Key Block
        a0_req = self.make_request(b"A0", b"0FFFS#21T2B00E00")
        a0_resp = self.hsm.process_raw_message(a0_req, header_length=4)
        dek_str, _ = _extract_key_string(a0_resp[8:].decode("ascii"))
        self.assertTrue(dek_str.startswith("S0009621TB00E0000") or dek_str.startswith("S1009621TB00E0000") or dek_str.startswith("S"))

        # Step 2: Encrypt with M0 ECB
        plaintext_hex = "0123456789ABCDEF"  # 8 bytes (16 hex chars)
        msg_len_hex = "0008"
        m0_payload = f"0011FFF{dek_str}{msg_len_hex}{plaintext_hex}".encode("ascii")
        m0_req = self.make_request(b"M0", m0_payload)
        m0_resp = self.hsm.process_raw_message(m0_req, header_length=4)

        self.assertTrue(m0_resp.startswith(b"0000M1000008"))
        ciphertext_hex = m0_resp[12:].decode("ascii")

        # Step 3: Decrypt with M2 ECB
        m2_payload = f"0011FFF{dek_str}{msg_len_hex}{ciphertext_hex}".encode("ascii")
        m2_req = self.make_request(b"M2", m2_payload)
        m2_resp = self.hsm.process_raw_message(m2_req, header_length=4)

        self.assertEqual(m2_resp, b"0000M3000008" + plaintext_hex.encode("ascii"))


if __name__ == "__main__":
    unittest.main()

