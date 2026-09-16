#!/usr/bin/env python3
"""
Empirical Verification and Adversarial Stress Test Harness for Milestone M4 Iteration 2.
Evaluates Data Protection (M0-M5), MAC Processing (M6-M9), and EMV Processing (KQ/KR, KU/KV, KY/KZ).

Target Modules:
- pythales/commands/mac_data.py (M0/M1, M2/M3, M4/M5, M6/M7, M8/M9)
- pythales/commands/emv.py (KQ/KR, KU/KV, KY/KZ)
- pythales/hsm.py

Challenger: challenger_m4_it2_1
"""

import unittest
import struct
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes
from pythales.core.frame import ResponseFrame
from pythales.commands.emv import derive_emv_session_key
from pythales.commands.mac_data import iso9797_alg3_mac, parse_payload_data_and_rem, parse_m4_modes, parse_mode_and_datalen


def make_request(header: bytes, cmd: str, payload: bytes) -> bytes:
    msg = header + cmd.encode("ascii") + payload
    return struct.pack("!H", len(msg)) + msg


def parse_resp(raw_resp: bytes, header_len: int = 4) -> ResponseFrame:
    header = raw_resp[:header_len]
    resp_code = raw_resp[header_len:header_len+2].decode("ascii", errors="ignore")
    err_code = raw_resp[header_len+2:header_len+4].decode("ascii", errors="ignore")
    payload = raw_resp[header_len+4:]
    return ResponseFrame(header_bytes=header, response_code=resp_code, error_code=err_code, payload_bytes=payload)


class TestM4Iteration2Empirical(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="HDR1")
        # Generate DEK 1 (Key Type 00B) under LMK
        a0_req1 = make_request(b"HDR1", "A0", b"000BU")
        a0_resp1 = parse_resp(self.hsm.process_raw_message(a0_req1))
        self.assertEqual(a0_resp1.error_code, ErrorCodes.SUCCESS)
        self.dek1 = a0_resp1.payload_bytes[:33].decode("ascii")

        # Generate DEK 2 (Key Type 00B) under LMK
        a0_resp2 = parse_resp(self.hsm.process_raw_message(a0_req1))
        self.assertEqual(a0_resp2.error_code, ErrorCodes.SUCCESS)
        self.dek2 = a0_resp2.payload_bytes[:33].decode("ascii")

        # Generate TAK/ZAK (Key Type 00A) under LMK
        a0_mac_req = make_request(b"HDR1", "A0", b"000AU")
        a0_mac_resp = parse_resp(self.hsm.process_raw_message(a0_mac_req))
        self.assertEqual(a0_mac_resp.error_code, ErrorCodes.SUCCESS)
        self.tak_key = a0_mac_resp.payload_bytes[:33].decode("ascii")

        # Generate MDK/IMK (Key Type 000) under LMK
        a0_mdk_req = make_request(b"HDR1", "A0", b"0000U")
        a0_mdk_resp = parse_resp(self.hsm.process_raw_message(a0_mdk_req))
        self.assertEqual(a0_mdk_resp.error_code, ErrorCodes.SUCCESS)
        self.mdk_key = a0_mdk_resp.payload_bytes[:33].decode("ascii")

    # =========================================================================
    # 1. Plain ASCII Plaintext with 16-Hex IV / Suffix Disambiguation
    # =========================================================================
    def test_ascii_plaintext_with_16hex_iv_in_m0_and_m2(self):
        """
        Challenge Edge Case 1:
        Plain ASCII string containing all-hex characters e.g. "1234567890123456" (16 bytes)
        with an attached 16-hex IV e.g. "0102030405060708". Total payload string after data_len is 32 chars.
        Must parse as ASCII data + IV, encrypt properly, and decrypt back to exact ASCII bytes.
        """
        ascii_plain = "1234567890123456" # 16 ASCII bytes (which happen to be valid hex digits)
        iv_hex = "0102030405060708"      # 16-hex IV
        data_len_hex = "0010"            # 16 bytes decimal

        # Encrypt M0 in CBC mode ('01')
        m0_payload = f"{self.dek1}01{data_len_hex}{ascii_plain}{iv_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.response_code, "M1")
        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_hex = m0_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(enc_hex), 48) # 16 bytes padded to 24 bytes PKCS5 = 48 hex chars

        # Decrypt M2 in CBC mode ('01')
        enc_data_len_hex = f"{len(enc_hex)//2:04X}"
        m2_payload = f"{self.dek1}01{enc_data_len_hex}{enc_hex}{iv_hex}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.response_code, "M3")
        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        dec_ascii = unhexlify(m2_resp.payload_bytes).decode("ascii")
        self.assertEqual(dec_ascii, ascii_plain)

    def test_ascii_plaintext_in_m6_m8_mac_processing(self):
        """
        Challenge Edge Case 1 (MAC):
        Pass plain ASCII plaintext "1234567890123456" (16 bytes) into M6 MAC generation and M8 verification.
        Ensure payload disambiguator extracts 16 ASCII bytes without unhexlify error or offset mismatch.
        """
        ascii_plain = "1234567890123456"
        data_len_hex = "0010" # 16 bytes

        # M6 Generate MAC (ISO Alg 3 mode '01')
        m6_payload = f"{self.tak_key}01{data_len_hex}{ascii_plain}".encode("ascii")
        m6_req = make_request(b"HDR1", "M6", m6_payload)
        m6_resp = parse_resp(self.hsm.process_raw_message(m6_req))

        self.assertEqual(m6_resp.response_code, "M7")
        self.assertEqual(m6_resp.error_code, ErrorCodes.SUCCESS)
        mac_hex = m6_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(mac_hex), 16)

        # M8 Verify MAC
        m8_payload = f"{self.tak_key}01{data_len_hex}{mac_hex}{ascii_plain}".encode("ascii")
        m8_req = make_request(b"HDR1", "M8", m8_payload)
        m8_resp = parse_resp(self.hsm.process_raw_message(m8_req))

        self.assertEqual(m8_resp.response_code, "M9")
        self.assertEqual(m8_resp.error_code, ErrorCodes.SUCCESS)

    def test_ascii_plaintext_in_kq_arqc_verification(self):
        """
        Challenge Edge Case 1 (KQ ARQC):
        ASCII transaction data "1234567890123456" with attached 16-hex ARQC in KQ Mode 2 (Verify ARQC).
        Ensures signature matcher distinguishes 16 ASCII txn bytes + 16-hex ARQC from hex data.
        """
        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0005"
        ascii_txn = "1234567890123456"
        data_len_hex = "0010" # 16 bytes ASCII

        # Generate ARQC with Mode 1
        kq_gen = f"1{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{ascii_txn}".encode("ascii")
        kq_gen_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_gen)))
        self.assertEqual(kq_gen_resp.error_code, ErrorCodes.SUCCESS)
        arqc_hex = kq_gen_resp.payload_bytes.decode("ascii")

        # Verify ARQC with Mode 2
        kq_ver = f"2{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{ascii_txn}{arqc_hex}".encode("ascii")
        kq_ver_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_ver)))
        self.assertEqual(kq_ver_resp.error_code, ErrorCodes.SUCCESS)

    # =========================================================================
    # 2. M4 1-Character vs 2-Character Mode Flags Stress Test
    # =========================================================================
    def test_m4_all_mode_combinations_1char_vs_2char(self):
        """
        Challenge Edge Case 2:
        Test M4 data translation across all permutations of 1-char and 2-char mode flags:
        - 2-char / 2-char ("00", "01")
        - 1-char / 1-char ("0", "1")
        - 2-char / 1-char ("00", "1")
        - 1-char / 2-char ("0", "01")
        Verify mode parser does not misidentify concatenated single-digit modes.
        """
        plaintext_hex = "8877665544332211"
        data_len_hex = "0008"

        # Encrypt under DEK1 (ECB '00')
        m0_payload = f"{self.dek1}00{data_len_hex}{plaintext_hex}".encode("ascii")
        enc_dek1_hex = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M0", m0_payload))).payload_bytes.decode("ascii")
        enc_len_hex = f"{len(enc_dek1_hex)//2:04X}"

        tgt_iv_hex = "A1B2C3D4E5F67890"

        modes_to_test = [
            ("00", "01", True),   # 2-char ECB -> 2-char CBC
            ("0", "1", True),     # 1-char ECB -> 1-char CBC
            ("00", "1", True),    # 2-char ECB -> 1-char CBC
            ("0", "01", True),    # 1-char ECB -> 2-char CBC
            ("00", "00", False),  # 2-char ECB -> 2-char ECB
            ("0", "0", False),    # 1-char ECB -> 1-char ECB
        ]

        for src_m, tgt_m, requires_tgt_iv in modes_to_test:
            iv_part = f"0000000000000000{tgt_iv_hex}" if requires_tgt_iv else ""
            m4_payload = f"{self.dek1}{self.dek2}{src_m}{tgt_m}{enc_len_hex}{enc_dek1_hex}{iv_part}".encode("ascii")
            m4_req = make_request(b"HDR1", "M4", m4_payload)
            m4_resp = parse_resp(self.hsm.process_raw_message(m4_req))

            self.assertEqual(m4_resp.error_code, ErrorCodes.SUCCESS, f"M4 failed for src_mode={src_m}, tgt_mode={tgt_m}")
            enc_dek2_hex = m4_resp.payload_bytes.decode("ascii")

            # Decrypt with M2 to verify payload integrity
            dec_mode = tgt_m
            m2_iv_part = tgt_iv_hex if requires_tgt_iv else ""
            enc2_len_hex = f"{len(enc_dek2_hex)//2:04X}"
            m2_payload = f"{self.dek2}{dec_mode}{enc2_len_hex}{enc_dek2_hex}{m2_iv_part}".encode("ascii")
            m2_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M2", m2_payload)))

            self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
            self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    # =========================================================================
    # 3. ECB to CBC Data Translation with Target IV
    # =========================================================================
    def test_m4_ecb_to_cbc_translation_with_target_iv(self):
        """
        Challenge Edge Case 3:
        Translate data block encrypted in ECB mode under SrcDEK to CBC mode under TgtDEK with explicit target IV.
        Confirm target IV is read correctly without reading dummy source IV or losing offset alignment.
        """
        plaintext_hex = "FEDCBA9876543210123456789ABCDEF0"
        data_len_hex = "0010"

        # Encrypt under SrcDEK in ECB mode ('00')
        m0_payload = f"{self.dek1}00{data_len_hex}{plaintext_hex}".encode("ascii")
        m0_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M0", m0_payload)))
        enc_src_hex = m0_resp.payload_bytes.decode("ascii")
        enc_len_hex = f"{len(enc_src_hex)//2:04X}"

        tgt_iv_hex = "FEDCBA9876543210"

        # Translate ECB ('00') -> CBC ('01')
        # Single 16-hex IV passed in payload is target IV
        m4_payload = f"{self.dek1}{self.dek2}0001{enc_len_hex}{enc_src_hex}{tgt_iv_hex}".encode("ascii")
        m4_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M4", m4_payload)))

        self.assertEqual(m4_resp.response_code, "M5")
        self.assertEqual(m4_resp.error_code, ErrorCodes.SUCCESS)
        enc_tgt_hex = m4_resp.payload_bytes.decode("ascii")

        # Decrypt under TgtDEK in CBC mode ('01') with target IV
        enc_tgt_len_hex = f"{len(enc_tgt_hex)//2:04X}"
        m2_payload = f"{self.dek2}01{enc_tgt_len_hex}{enc_tgt_hex}{tgt_iv_hex}".encode("ascii")
        m2_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M2", m2_payload)))

        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    def test_m4_cbc_to_ecb_translation_with_source_iv(self):
        """
        Challenge Edge Case 3 (Reverse):
        Translate data block encrypted in CBC mode under SrcDEK with source IV to ECB mode under TgtDEK.
        Confirm source IV is read correctly and target ECB payload has no IV.
        """
        plaintext_hex = "11112222333344445555666677778888"
        src_iv_hex = "9988776655443322"
        data_len_hex = "0010"

        # Encrypt under SrcDEK in CBC mode ('01') with src_iv
        m0_payload = f"{self.dek1}01{data_len_hex}{plaintext_hex}{src_iv_hex}".encode("ascii")
        enc_src_hex = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M0", m0_payload))).payload_bytes.decode("ascii")
        enc_len_hex = f"{len(enc_src_hex)//2:04X}"

        # Translate CBC ('01') -> ECB ('00') with src_iv
        m4_payload = f"{self.dek1}{self.dek2}0100{enc_len_hex}{enc_src_hex}{src_iv_hex}".encode("ascii")
        m4_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M4", m4_payload)))

        self.assertEqual(m4_resp.error_code, ErrorCodes.SUCCESS)
        enc_tgt_hex = m4_resp.payload_bytes.decode("ascii")

        # Decrypt under TgtDEK in ECB mode ('00')
        enc_tgt_len_hex = f"{len(enc_tgt_hex)//2:04X}"
        m2_payload = f"{self.dek2}00{enc_tgt_len_hex}{enc_tgt_hex}".encode("ascii")
        m2_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "M2", m2_payload)))

        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    # =========================================================================
    # 4. EMV ARQC Verification with IMK and PAN/PSN (CSKD UDK Derivation)
    # =========================================================================
    def test_kq_arqc_verification_with_imk_and_pan_psn(self):
        """
        Challenge Edge Case 4:
        Test EMV ARQC generation (Mode 1), verification (Mode 2), and ARPC generation (Mode 0)
        using Issuer Master Key (IMK) and PAN/PSN (CSKD Option 1 UDK derivation).
        """
        imk_key = self.mdk_key
        pan = "4532015588991234"
        psn = "02"
        atc_hex = "01A4"
        txn_data_hex = "000000005000000000000000084000000000084026040100ABCD1234"
        data_len_hex = f"{len(txn_data_hex)//2:04X}"

        # 1. Generate ARQC (Mode 1)
        kq_m1 = f"1{imk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}".encode("ascii")
        m1_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_m1)))
        self.assertEqual(m1_resp.response_code, "KR")
        self.assertEqual(m1_resp.error_code, ErrorCodes.SUCCESS)
        computed_arqc = m1_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(computed_arqc), 16)

        # Verify independently using derive_emv_session_key
        raw_imk = unhexlify(imk_key[1:]) if imk_key.startswith("U") else unhexlify(imk_key)
        # Note: in pythales _get_key_raw decrypts key under LMK, let's verify via KQ Mode 2
        # 2. Verify ARQC (Mode 2) - should PASS ('00')
        kq_m2_pass = f"2{imk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{computed_arqc}".encode("ascii")
        m2_pass_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_m2_pass)))
        self.assertEqual(m2_pass_resp.response_code, "KR")
        self.assertEqual(m2_pass_resp.error_code, ErrorCodes.SUCCESS)

        # 3. Verify ARQC (Mode 2) with tampered ARQC - should FAIL ('05' PIN_VERIFICATION_FAILED)
        tampered_arqc = "1234567890ABCDEF"
        if tampered_arqc == computed_arqc:
            tampered_arqc = "0000000000000000"
        kq_m2_fail = f"2{imk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{tampered_arqc}".encode("ascii")
        m2_fail_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_m2_fail)))
        self.assertEqual(m2_fail_resp.response_code, "KR")
        self.assertEqual(m2_fail_resp.error_code, ErrorCodes.PIN_VERIFICATION_FAILED)

        # 4. Verify ARQC and Generate ARPC (Mode 0)
        arc_hex = "3030"
        kq_m0 = f"0{imk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{computed_arqc}{arc_hex}".encode("ascii")
        m0_resp = parse_resp(self.hsm.process_raw_message(make_request(b"HDR1", "KQ", kq_m0)))
        self.assertEqual(m0_resp.response_code, "KR")
        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        arpc_hex = m0_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(arpc_hex), 16)

    # =========================================================================
    # 5. Full Sweep of Remaining M4 Commands: KU/KV and KY/KZ
    # =========================================================================
    def test_ku_kv_script_encryption_decryption_sweep(self):
        """Test EMV KU script encryption and KV script decryption end-to-end."""
        atc_hex = "00FF"
        script_hex = "8418800000081122334455667788"
        data_len_hex = f"{len(script_hex)//2:04X}"

        # KU Encrypt Script
        ku_req = make_request(b"HDR1", "KU", f"{self.mdk_key}{atc_hex}{data_len_hex}{script_hex}".encode("ascii"))
        ku_resp = parse_resp(self.hsm.process_raw_message(ku_req))
        self.assertEqual(ku_resp.response_code, "KV")
        self.assertEqual(ku_resp.error_code, ErrorCodes.SUCCESS)
        enc_script = ku_resp.payload_bytes.decode("ascii")

        # KV Decrypt Script
        enc_len_hex = f"{len(enc_script)//2:04X}"
        kv_req = make_request(b"HDR1", "KV", f"{self.mdk_key}{atc_hex}{enc_len_hex}{enc_script}".encode("ascii"))
        kv_resp = parse_resp(self.hsm.process_raw_message(kv_req))
        self.assertEqual(kv_resp.response_code, "KW")
        self.assertEqual(kv_resp.error_code, ErrorCodes.SUCCESS)
        dec_script = kv_resp.payload_bytes.decode("ascii")

        self.assertEqual(dec_script, script_hex)

    def test_ky_kz_script_mac_generation(self):
        """Test EMV KY script MAC generation (ISO Alg 3 MAC over SK_SMI)."""
        atc_hex = "0100"
        script_hex = "841880000008AABBCCDDEEFF0011"
        data_len_hex = f"{len(script_hex)//2:04X}"

        ky_req = make_request(b"HDR1", "KY", f"{self.mdk_key}{atc_hex}{data_len_hex}{script_hex}".encode("ascii"))
        ky_resp = parse_resp(self.hsm.process_raw_message(ky_req))
        self.assertEqual(ky_resp.response_code, "KZ")
        self.assertEqual(ky_resp.error_code, ErrorCodes.SUCCESS)
        mac_hex = ky_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(mac_hex), 16)


if __name__ == "__main__":
    unittest.main()
