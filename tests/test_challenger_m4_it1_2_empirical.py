#!/usr/bin/env python3
"""
Empirical Boundary & Stress Test Suite for Milestone M4 (Iteration 1).
Targets:
- pythales/commands/mac_data.py (M0/M1, M2/M3, M4/M5, M6/M7, M8/M9)
- pythales/commands/emv.py (KQ/KR, KU/KV, KY/KZ)

Executed by challenger_m4_it1_2.
"""

import unittest
import struct
from binascii import hexlify, unhexlify
from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes
from pythales.core.frame import ResponseFrame


def make_request(header: bytes, cmd: str, payload: bytes) -> bytes:
    msg = header + cmd.encode("ascii") + payload
    return struct.pack("!H", len(msg)) + msg


def parse_resp(raw_resp: bytes, header_len: int = 4) -> ResponseFrame:
    header = raw_resp[:header_len]
    resp_code = raw_resp[header_len:header_len+2].decode("ascii", errors="ignore")
    err_code = raw_resp[header_len+2:header_len+4].decode("ascii", errors="ignore")
    payload = raw_resp[header_len+4:]
    return ResponseFrame(header_bytes=header, response_code=resp_code, error_code=err_code, payload_bytes=payload)


class TestM4EmpiricalAdversarial(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="HDR1")
        # Generate a DEK under LMK using A0 mode 0, type 00B
        a0_req = make_request(b"HDR1", "A0", b"000BU")
        a0_resp = parse_resp(self.hsm.process_raw_message(a0_req))
        self.assertEqual(a0_resp.error_code, ErrorCodes.SUCCESS)
        # A0 returns Key (33 chars) + KCV (6 chars)
        self.dek1 = a0_resp.payload_bytes[:33].decode("ascii")

        # Generate a second DEK
        a0_resp2 = parse_resp(self.hsm.process_raw_message(a0_req))
        self.assertEqual(a0_resp2.error_code, ErrorCodes.SUCCESS)
        self.dek2 = a0_resp2.payload_bytes[:33].decode("ascii")

        # Generate a TAK/ZAK key for MAC (type 00A)
        a0_mac_req = make_request(b"HDR1", "A0", b"000AU")
        a0_mac_resp = parse_resp(self.hsm.process_raw_message(a0_mac_req))
        self.assertEqual(a0_mac_resp.error_code, ErrorCodes.SUCCESS)
        self.tak_key = a0_mac_resp.payload_bytes[:33].decode("ascii")

        # MDK Key for EMV (type 000)
        a0_mdk_req = make_request(b"HDR1", "A0", b"0000U")
        a0_mdk_resp = parse_resp(self.hsm.process_raw_message(a0_mdk_req))
        self.assertEqual(a0_mdk_resp.error_code, ErrorCodes.SUCCESS)
        self.mdk_key = a0_mdk_resp.payload_bytes[:33].decode("ascii")

    # -------------------------------------------------------------------------
    # 1. Data Protection Commands: M0/M1 (Encrypt Data), M2/M3 (Decrypt Data)
    # -------------------------------------------------------------------------
    def test_m0_m2_ecb_roundtrip(self):
        """Test M0 ECB encryption and M2 ECB decryption roundtrip."""
        plaintext_hex = "1122334455667788"
        data_len_hex = "0008"
        # M0 payload: [DEK] + Mode '00' + DataLen '0008' + PlaintextHex
        m0_payload = f"{self.dek1}00{data_len_hex}{plaintext_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.response_code, "M1")
        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_hex = m0_resp.payload_bytes.decode("ascii")
        self.assertTrue(len(enc_hex) >= 16)

        # M2 payload: [DEK] + Mode '00' + DataLen (len of ciphertext bytes) + EncHex
        enc_len_hex = f"{len(enc_hex)//2:04X}"
        m2_payload = f"{self.dek1}00{enc_len_hex}{enc_hex}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.response_code, "M3")
        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        dec_hex = m2_resp.payload_bytes.decode("ascii")
        self.assertEqual(dec_hex, plaintext_hex)

    def test_m0_m2_cbc_roundtrip(self):
        """Test M0 CBC encryption and M2 CBC decryption roundtrip with non-zero IV."""
        plaintext_hex = "0102030405060708090A0B0C0D0E0F10"
        iv_hex = "1234567890ABCDEF"
        data_len_hex = "0010"
        # M0 payload: [DEK] + Mode '01' + DataLen '0010' + PlaintextHex + IV
        m0_payload = f"{self.dek1}01{data_len_hex}{plaintext_hex}{iv_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.response_code, "M1")
        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_hex = m0_resp.payload_bytes.decode("ascii")

        # M2 payload: [DEK] + Mode '01' + DataLen (len of ciphertext bytes) + EncHex + IV
        enc_len_hex = f"{len(enc_hex)//2:04X}"
        m2_payload = f"{self.dek1}01{enc_len_hex}{enc_hex}{iv_hex}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.response_code, "M3")
        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    def test_m0_m2_ctr_roundtrip(self):
        """Test M0 CTR encryption and M2 CTR decryption roundtrip."""
        plaintext_hex = "AABBCCDDEEFF00112233"
        iv_hex = "0000000000000001"
        data_len_hex = "000A"
        # Mode '06'
        m0_payload = f"{self.dek1}06{data_len_hex}{plaintext_hex}{iv_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_hex = m0_resp.payload_bytes.decode("ascii")

        m2_payload = f"{self.dek1}06{data_len_hex}{enc_hex}{iv_hex}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    def test_m0_m2_ff1_fpe_roundtrip(self):
        """Test M0 FF1 FPE encryption and M2 FF1 FPE decryption roundtrip."""
        digits = "1234567890123456"
        data_len_hex = f"{len(digits):04X}"
        m0_payload = f"{self.dek1}11{data_len_hex}{digits}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_digits = m0_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(enc_digits), len(digits))
        self.assertTrue(enc_digits.isdigit())

        m2_payload = f"{self.dek1}11{data_len_hex}{enc_digits}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), digits)

    def test_m0_short_payload_boundary(self):
        """M0 payload shorter than 38 chars should return INVALID_DATA_LENGTH."""
        m0_payload = b"U12345"
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertEqual(m0_resp.response_code, "M1")
        self.assertEqual(m0_resp.error_code, ErrorCodes.INVALID_DATA_LENGTH)

    def test_m0_invalid_mode_boundary(self):
        """M0 payload with unsupported mode should return error code without crashing."""
        m0_payload = f"{self.dek1}9900081122334455667788".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))

        self.assertIn(m0_resp.error_code, (ErrorCodes.INVALID_DATA_LENGTH, ErrorCodes.FUNCTION_NOT_SUPPORTED))

    def test_m2_invalid_hex_data_boundary(self):
        """M2 payload with invalid hex string should return error gracefully without crashing."""
        m2_payload = f"{self.dek1}000008ZZZZZZZZZZZZZZZZ".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertIn(m2_resp.error_code, (ErrorCodes.INVALID_DATA_LENGTH, ErrorCodes.FUNCTION_NOT_SUPPORTED))

    # -------------------------------------------------------------------------
    # 2. Data Protection Commands: M4/M5 (Translate Data Block)
    # -------------------------------------------------------------------------
    def test_m4_translate_ecb_to_cbc(self):
        """Test M4 translate data block from ECB (DEK1) to CBC (DEK2)."""
        plaintext_hex = "1122334455667788"
        data_len_hex = "0008"

        # Encrypt under DEK1 (ECB mode '00')
        m0_payload = f"{self.dek1}00{data_len_hex}{plaintext_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))
        self.assertEqual(m0_resp.error_code, ErrorCodes.SUCCESS)
        enc_dek1_hex = m0_resp.payload_bytes.decode("ascii")

        # Translate M4: DEK1 (mode '00') -> DEK2 (mode '01')
        enc_len_hex = f"{len(enc_dek1_hex)//2:04X}"
        tgt_iv_hex = "1234567890ABCDEF"
        m4_payload = f"{self.dek1}{self.dek2}0001{enc_len_hex}{enc_dek1_hex}0000000000000000{tgt_iv_hex}".encode("ascii")
        m4_req = make_request(b"HDR1", "M4", m4_payload)
        m4_resp = parse_resp(self.hsm.process_raw_message(m4_req))

        self.assertEqual(m4_resp.response_code, "M5")
        self.assertEqual(m4_resp.error_code, ErrorCodes.SUCCESS)
        enc_dek2_hex = m4_resp.payload_bytes.decode("ascii")

        # Decrypt under DEK2 (CBC mode '01')
        enc2_len_hex = f"{len(enc_dek2_hex)//2:04X}"
        m2_payload = f"{self.dek2}01{enc2_len_hex}{enc_dek2_hex}{tgt_iv_hex}".encode("ascii")
        m2_req = make_request(b"HDR1", "M2", m2_payload)
        m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))

        self.assertEqual(m2_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(m2_resp.payload_bytes.decode("ascii"), plaintext_hex)

    def test_m4_single_digit_modes_boundary(self):
        """Boundary test M4 with 1-char modes '0' and '0' (ECB to ECB)."""
        plaintext_hex = "1122334455667788"
        data_len_hex = "0008"

        m0_payload = f"{self.dek1}00{data_len_hex}{plaintext_hex}".encode("ascii")
        m0_req = make_request(b"HDR1", "M0", m0_payload)
        m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))
        enc_dek1_hex = m0_resp.payload_bytes.decode("ascii")

        m4_payload = f"{self.dek1}{self.dek2}00{data_len_hex}{enc_dek1_hex}".encode("ascii")
        m4_req = make_request(b"HDR1", "M4", m4_payload)
        m4_resp = parse_resp(self.hsm.process_raw_message(m4_req))

        self.assertEqual(m4_resp.response_code, "M5")

    def test_m4_short_payload_boundary(self):
        """M4 short payload < 70 chars should return INVALID_DATA_LENGTH."""
        m4_payload = f"{self.dek1}".encode("ascii")
        m4_req = make_request(b"HDR1", "M4", m4_payload)
        m4_resp = parse_resp(self.hsm.process_raw_message(m4_req))

        self.assertEqual(m4_resp.response_code, "M5")
        self.assertEqual(m4_resp.error_code, ErrorCodes.INVALID_DATA_LENGTH)

    # -------------------------------------------------------------------------
    # 3. MAC Generation & Verification: M6/M7, M8/M9
    # -------------------------------------------------------------------------
    def test_m6_m8_iso9797_alg1_mac(self):
        """Test M6 MAC Generation (ISO Alg 1) and M8 Verification."""
        data_hex = "11223344556677889900AABBCCDDEEFF"
        data_len_hex = "0010"

        # M6 payload: [TAK] + Mode '00' + DataLen '0010' + DataHex
        m6_payload = f"{self.tak_key}00{data_len_hex}{data_hex}".encode("ascii")
        m6_req = make_request(b"HDR1", "M6", m6_payload)
        m6_resp = parse_resp(self.hsm.process_raw_message(m6_req))

        self.assertEqual(m6_resp.response_code, "M7")
        self.assertEqual(m6_resp.error_code, ErrorCodes.SUCCESS)
        mac_hex = m6_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(mac_hex), 16)

        # M8 payload: [TAK] + Mode '00' + DataLen '0010' + MACHex + DataHex
        m8_payload = f"{self.tak_key}00{data_len_hex}{mac_hex}{data_hex}".encode("ascii")
        m8_req = make_request(b"HDR1", "M8", m8_payload)
        m8_resp = parse_resp(self.hsm.process_raw_message(m8_req))

        self.assertEqual(m8_resp.response_code, "M9")
        self.assertEqual(m8_resp.error_code, ErrorCodes.SUCCESS)

    def test_m6_m8_iso9797_alg3_mac(self):
        """Test M6 MAC Generation (ISO Alg 3 Retail MAC) and M8 Verification."""
        data_hex = "0102030405060708090A"
        data_len_hex = "000A"

        # Mode '01'
        m6_payload = f"{self.tak_key}01{data_len_hex}{data_hex}".encode("ascii")
        m6_req = make_request(b"HDR1", "M6", m6_payload)
        m6_resp = parse_resp(self.hsm.process_raw_message(m6_req))

        self.assertEqual(m6_resp.error_code, ErrorCodes.SUCCESS)
        mac_hex = m6_resp.payload_bytes.decode("ascii")

        # Verify correct MAC
        m8_payload = f"{self.tak_key}01{data_len_hex}{mac_hex}{data_hex}".encode("ascii")
        m8_req = make_request(b"HDR1", "M8", m8_payload)
        m8_resp = parse_resp(self.hsm.process_raw_message(m8_req))
        self.assertEqual(m8_resp.error_code, ErrorCodes.SUCCESS)

    def test_m8_mac_verification_mismatch_boundary(self):
        """M8 verification with wrong MAC string should return KCV_MISMATCH ('05')."""
        data_hex = "0102030405060708"
        data_len_hex = "0008"
        bad_mac_hex = "FFFFFFFFFFFFFFFF"

        m8_payload = f"{self.tak_key}00{data_len_hex}{bad_mac_hex}{data_hex}".encode("ascii")
        m8_req = make_request(b"HDR1", "M8", m8_payload)
        m8_resp = parse_resp(self.hsm.process_raw_message(m8_req))

        self.assertEqual(m8_resp.response_code, "M9")
        self.assertEqual(m8_resp.error_code, ErrorCodes.KCV_MISMATCH)

    def test_m6_cmac_mode(self):
        """Test M6 CMAC generation (mode '02')."""
        data_hex = "010203040506070809"
        data_len_hex = "0009"

        m6_payload = f"{self.tak_key}02{data_len_hex}{data_hex}".encode("ascii")
        m6_req = make_request(b"HDR1", "M6", m6_payload)
        m6_resp = parse_resp(self.hsm.process_raw_message(m6_req))

        self.assertEqual(m6_resp.response_code, "M7")
        self.assertEqual(m6_resp.error_code, ErrorCodes.SUCCESS)
        self.assertEqual(len(m6_resp.payload_bytes.decode("ascii")), 16)

    # -------------------------------------------------------------------------
    # 4. EMV Processing: KQ/KR (ARQC/ARPC), KU/KV (Script Enc/Dec), KY/KZ (Script MAC)
    # -------------------------------------------------------------------------
    def test_kq_mode_1_generate_arqc(self):
        """Test KQ Mode 1: Generate ARQC."""
        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0012"
        txn_data_hex = "00000000100000000000000008400000000008402604010012345678"
        data_len_hex = f"{len(txn_data_hex)//2:04X}"

        kq_payload = f"1{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}".encode("ascii")
        kq_req = make_request(b"HDR1", "KQ", kq_payload)
        kq_resp = parse_resp(self.hsm.process_raw_message(kq_req))

        self.assertEqual(kq_resp.response_code, "KR")
        self.assertEqual(kq_resp.error_code, ErrorCodes.SUCCESS)
        arqc_hex = kq_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(arqc_hex), 16)

    def test_kq_mode_2_verify_arqc_pass(self):
        """Test KQ Mode 2: Verify ARQC matching."""
        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0012"
        txn_data_hex = "00000000100000000000000008400000000008402604010012345678"
        data_len_hex = f"{len(txn_data_hex)//2:04X}"

        kq_gen_payload = f"1{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}".encode("ascii")
        kq_gen_req = make_request(b"HDR1", "KQ", kq_gen_payload)
        arqc_hex = parse_resp(self.hsm.process_raw_message(kq_gen_req)).payload_bytes.decode("ascii")

        kq_ver_payload = f"2{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{arqc_hex}".encode("ascii")
        kq_ver_req = make_request(b"HDR1", "KQ", kq_ver_payload)
        kq_ver_resp = parse_resp(self.hsm.process_raw_message(kq_ver_req))

        self.assertEqual(kq_ver_resp.response_code, "KR")
        self.assertEqual(kq_ver_resp.error_code, ErrorCodes.SUCCESS)

    def test_kq_mode_2_verify_arqc_mismatch_boundary(self):
        """Test KQ Mode 2: Verify ARQC failure returns PIN_VERIFICATION_FAILED ('05')."""
        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0012"
        txn_data_hex = "00000000100000000000000008400000000008402604010012345678"
        data_len_hex = f"{len(txn_data_hex)//2:04X}"
        bad_arqc = "0000000000000000"

        kq_ver_payload = f"2{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{bad_arqc}".encode("ascii")
        kq_ver_req = make_request(b"HDR1", "KQ", kq_ver_payload)
        kq_ver_resp = parse_resp(self.hsm.process_raw_message(kq_ver_req))

        self.assertEqual(kq_ver_resp.response_code, "KR")
        self.assertEqual(kq_ver_resp.error_code, ErrorCodes.PIN_VERIFICATION_FAILED)

    def test_kq_mode_0_verify_and_generate_arpc(self):
        """Test KQ Mode 0: Verify ARQC and Generate ARPC."""
        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0012"
        txn_data_hex = "000000001000"
        data_len_hex = f"{len(txn_data_hex)//2:04X}"
        arc_hex = "3030"

        kq_gen_payload = f"1{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}".encode("ascii")
        arqc_hex = parse_resp(self.hsm.process_raw_message(
            make_request(b"HDR1", "KQ", kq_gen_payload)
        )).payload_bytes.decode("ascii")

        kq_m0_payload = f"0{self.mdk_key}{pan};{psn}{atc_hex}{data_len_hex}{txn_data_hex}{arqc_hex}{arc_hex}".encode("ascii")
        kq_m0_req = make_request(b"HDR1", "KQ", kq_m0_payload)
        kq_m0_resp = parse_resp(self.hsm.process_raw_message(kq_m0_req))

        self.assertEqual(kq_m0_resp.response_code, "KR")
        self.assertEqual(kq_m0_resp.error_code, ErrorCodes.SUCCESS)
        arpc_hex = kq_m0_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(arpc_hex), 16)

    def test_ku_kv_emv_script_encryption_roundtrip(self):
        """Test KU script encryption and KV script decryption roundtrip."""
        atc_hex = "00AB"
        script_hex = "8418800000080102030405060708"
        data_len_hex = f"{len(script_hex)//2:04X}"

        ku_payload = f"{self.mdk_key}{atc_hex}{data_len_hex}{script_hex}".encode("ascii")
        ku_req = make_request(b"HDR1", "KU", ku_payload)
        ku_resp = parse_resp(self.hsm.process_raw_message(ku_req))

        self.assertEqual(ku_resp.response_code, "KV")
        self.assertEqual(ku_resp.error_code, ErrorCodes.SUCCESS)
        enc_script_hex = ku_resp.payload_bytes.decode("ascii")

        enc_data_len_hex = f"{len(enc_script_hex)//2:04X}"
        kv_payload = f"{self.mdk_key}{atc_hex}{enc_data_len_hex}{enc_script_hex}".encode("ascii")
        kv_req = make_request(b"HDR1", "KV", kv_payload)
        kv_resp = parse_resp(self.hsm.process_raw_message(kv_req))

        self.assertEqual(kv_resp.response_code, "KW")
        self.assertEqual(kv_resp.error_code, ErrorCodes.SUCCESS)
        dec_script_hex = kv_resp.payload_bytes.decode("ascii")
        self.assertEqual(dec_script_hex, script_hex)

    def test_ky_emv_script_mac(self):
        """Test KY script MAC generation (ISO Alg 3 under SK_SMI)."""
        atc_hex = "001A"
        script_hex = "8418800000080102030405060708"
        data_len_hex = f"{len(script_hex)//2:04X}"

        ky_payload = f"{self.mdk_key}{atc_hex}{data_len_hex}{script_hex}".encode("ascii")
        ky_req = make_request(b"HDR1", "KY", ky_payload)
        ky_resp = parse_resp(self.hsm.process_raw_message(ky_req))

        self.assertEqual(ky_resp.response_code, "KZ")
        self.assertEqual(ky_resp.error_code, ErrorCodes.SUCCESS)
        mac_hex = ky_resp.payload_bytes.decode("ascii")
        self.assertEqual(len(mac_hex), 16)


if __name__ == "__main__":
    unittest.main()
