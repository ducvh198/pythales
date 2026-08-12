"""
Unit tests for Command A0 supporting AES-256 DEK, ZMK, CVK, DEK under ZMK, and CVK under ZMK.
"""

import os
import struct
import unittest
from binascii import hexlify, unhexlify

from pythales.hsm import HSM
from pythales.core.frame import MessageFraming
from pythales.crypto.lmk import LMKEngine
from pythales.crypto.keyblock import TR31KeyBlock, parse_header
from pythales.core.errors import ErrorCodes


class TestA0KeyGeneration(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="1234")
        self.lmk = self.hsm.LMK

    def make_request(self, command_code: bytes, payload: bytes) -> bytes:
        body = b"1234" + command_code + payload
        return struct.pack("!H", len(body)) + body

    def parse_response(self, resp_raw: bytes):
        frame = MessageFraming.parse_request(resp_raw, header_length=4)
        self.assertEqual(frame.command_code, "A1")
        err_code = frame.raw_body[2:4].decode("ascii")
        self.assertEqual(err_code, ErrorCodes.SUCCESS)
        return frame.raw_body[4:].decode("ascii")

    def test_a0_mode0_dek_aes256_keyblock(self):
        """
        1. Test A0 Mode 0 generating AES-256 DEK in Thales Key Block format ('S' Scheme, 'A3' Algorithm, '21' Usage).
        """
        req = self.make_request(b"A0", b"0FFFS#21A3B00N00")
        resp_raw = self.hsm.process_raw_message(req)
        data = self.parse_response(resp_raw)

        self.assertTrue(data.startswith("S"))

        # Extract Key Block string
        target_len = int(data[1:5])
        kb_str = data[:target_len]
        kcv = data[target_len:]

        self.assertEqual(len(kcv), 6)

        # Unwrap key block under LMK
        hdr, clear_key = TR31KeyBlock.unwrap(kb_str, self.lmk)
        self.assertEqual(hdr.key_usage, "21")
        self.assertEqual(hdr.algorithm, "A")
        self.assertEqual(len(clear_key), 32)  # AES-256 is 32 bytes

        # Verify KCV matches AES-CMAC KCV
        expected_kcv = LMKEngine.generate_kcv(clear_key, algorithm="A3")
        self.assertEqual(kcv, expected_kcv)

    def test_a0_mode0_zmk_generation(self):
        """
        2. Test A0 Mode 0 generating ZMK in both Variant mode ('000U') and Key Block mode ('FFFS#52T2...').
        """
        # Variant mode ZMK (3DES Double-length)
        req_var = self.make_request(b"A0", b"0000U")
        data_var = self.parse_response(self.hsm.process_raw_message(req_var))
        self.assertTrue(data_var.startswith("U"))
        self.assertEqual(len(data_var), 33 + 6)

        # Key Block mode ZMK (3DES)
        req_kb = self.make_request(b"A0", b"0FFFS#52T2B00N00")
        data_kb = self.parse_response(self.hsm.process_raw_message(req_kb))
        self.assertTrue(data_kb.startswith("S"))
        target_len = int(data_kb[1:5])
        kb_str = data_kb[:target_len]
        hdr, clear_zmk = TR31KeyBlock.unwrap(kb_str, self.lmk)
        self.assertEqual(hdr.key_usage, "52")
        self.assertEqual(len(clear_zmk), 24)

        # Key Block mode AES-256 ZMK
        req_aes_zmk = self.make_request(b"A0", b"0FFFS#52A3B00N00")
        data_aes_zmk = self.parse_response(self.hsm.process_raw_message(req_aes_zmk))
        target_len_aes = int(data_aes_zmk[1:5])
        kb_str_aes = data_aes_zmk[:target_len_aes]
        hdr_aes, clear_aes_zmk = TR31KeyBlock.unwrap(kb_str_aes, self.lmk)
        self.assertEqual(hdr_aes.key_usage, "52")
        self.assertEqual(hdr_aes.algorithm, "A")
        self.assertEqual(len(clear_aes_zmk), 32)


    def test_a0_mode0_cvk_generation(self):
        """
        3. Test A0 Mode 0 generating CVK in both Variant mode ('0402U') and Key Block mode ('FFFS#C0T2...').
        """
        # Variant mode CVK
        req_var = self.make_request(b"A0", b"0402U")
        data_var = self.parse_response(self.hsm.process_raw_message(req_var))
        self.assertTrue(data_var.startswith("U"))

        # Key Block mode CVK
        req_kb = self.make_request(b"A0", b"0FFFS#C0T2N00N00")
        data_kb = self.parse_response(self.hsm.process_raw_message(req_kb))
        target_len = int(data_kb[1:5])
        kb_str = data_kb[:target_len]
        hdr, clear_cvk = TR31KeyBlock.unwrap(kb_str, self.lmk)
        self.assertEqual(hdr.key_usage, "C0")
        self.assertEqual(len(clear_cvk), 24)

    def test_a0_mode1_dek_aes256_under_zmk(self):
        """
        4. Test A0 Mode 1 generating AES-256 DEK under LMK and exporting under ZMK Key Block ('R' Scheme).
        """
        # Step 1: Generate a ZMK under LMK
        zmk_req = self.make_request(b"A0", b"0000S")
        zmk_data = self.parse_response(self.hsm.process_raw_message(zmk_req))
        zmk_len = int(zmk_data[1:5])
        zmk_lmk_str = zmk_data[:zmk_len]
        _, raw_zmk = TR31KeyBlock.unwrap(zmk_lmk_str, self.lmk)

        # Step 2: Generate AES-256 DEK under LMK and export under ZMK with TR-31 Scheme 'R'
        mode1_payload = f"1FFFS{zmk_lmk_str}R#21A3B00E00".encode("ascii")
        req_m1 = self.make_request(b"A0", mode1_payload)
        data_m1 = self.parse_response(self.hsm.process_raw_message(req_m1))

        # Extract Key under LMK
        len1 = int(data_m1[1:5])
        dek_lmk_str = data_m1[:len1]
        rem1 = data_m1[len1:]

        # Extract Key under ZMK
        len2 = int(rem1[1:5])
        dek_zmk_str = rem1[:len2]
        kcv = rem1[len2:]

        self.assertEqual(len(kcv), 6)

        # Unwrap DEK under LMK
        hdr_lmk, clear_dek_lmk = TR31KeyBlock.unwrap(dek_lmk_str, self.lmk)
        self.assertEqual(hdr_lmk.algorithm, "A")
        self.assertEqual(len(clear_dek_lmk), 32)

        # Unwrap DEK under ZMK
        hdr_zmk, clear_dek_zmk = TR31KeyBlock.unwrap(dek_zmk_str, raw_zmk)
        self.assertEqual(hdr_zmk.algorithm, "A")
        self.assertEqual(clear_dek_lmk, clear_dek_zmk)

        # KCV check
        expected_kcv = LMKEngine.generate_kcv(clear_dek_lmk, algorithm="A3")
        self.assertEqual(kcv, expected_kcv)

    def test_a0_mode1_cvk_under_zmk(self):
        """
        5. Test A0 Mode 1 generating CVK under LMK and exporting under ZMK.
        """
        # Step 1: Generate a ZMK under LMK
        zmk_req = self.make_request(b"A0", b"0000S")
        zmk_data = self.parse_response(self.hsm.process_raw_message(zmk_req))
        zmk_len = int(zmk_data[1:5])
        zmk_lmk_str = zmk_data[:zmk_len]
        _, raw_zmk = TR31KeyBlock.unwrap(zmk_lmk_str, self.lmk)

        # Step 2: Generate CVK under LMK and export under ZMK (TR-31 Scheme 'R')
        mode1_payload = f"1FFFS{zmk_lmk_str}R#C0T2N00E00".encode("ascii")
        req_m1 = self.make_request(b"A0", mode1_payload)
        data_m1 = self.parse_response(self.hsm.process_raw_message(req_m1))

        len1 = int(data_m1[1:5])
        cvk_lmk_str = data_m1[:len1]
        rem1 = data_m1[len1:]

        len2 = int(rem1[1:5])
        cvk_zmk_str = rem1[:len2]
        kcv = rem1[len2:]

        self.assertEqual(len(kcv), 6)

        hdr_lmk, clear_cvk_lmk = TR31KeyBlock.unwrap(cvk_lmk_str, self.lmk)
        self.assertEqual(hdr_lmk.key_usage, "C0")

        hdr_zmk, clear_cvk_zmk = TR31KeyBlock.unwrap(cvk_zmk_str, raw_zmk)
        self.assertEqual(clear_cvk_lmk, clear_cvk_zmk)



if __name__ == "__main__":
    unittest.main()
