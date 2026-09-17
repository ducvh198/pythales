"""
Comprehensive test suite for Thales payShield 10K HMAC Commands Suite (Section 7.1 & Section 12):
- L0/L1: Generate HMAC Secret Key
- LQ/LR: Generate HMAC on a Block of Data
- LS/LT: Verify HMAC on a Block of Data
- LU/LV: Import HMAC Key under ZMK
- LW/LX: Export HMAC Key under ZMK
- LY/LZ: Translate HMAC Key (Old LMK to Current LMK / Variant to Key Block)
- BU/BV: Key Check Value calculation for HMAC Keys
- Trailer handling with 0x19 delimiter
- Error codes verification (00, 01, 04, 05, 06, 07, 08, 15)
"""

import hmac
import hashlib
import os
import unittest
from binascii import hexlify, unhexlify

from pythales.hsm import HSM, DummyMessage, LQ, LS, L0, LU, LW, LY
from pythales.core.errors import ErrorCodes
from pythales.crypto.keyblock import TR31KeyBlock, TR31Header


class TestHMACSuite(unittest.TestCase):
    def setUp(self):
        self.lmk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        self.hsm = HSM(header=b"HDR1", key=hexlify(self.lmk).decode("ascii"))

    def test_l0_generate_hmac_key_variant_and_keyblock(self):
        """Test L0/L1 generating HMAC keys under Variant LMK and Key Block LMK."""
        # 1. Variant LMK: SHA-256 (Hash ID 06), Usage 03 (Gen & Ver), Length 32 bytes (0032), Format 00
        req_l0_var = b"HDR1L00603003200"
        resp_l0_var = self.hsm.process_raw_message(req_l0_var)
        self.assertTrue(resp_l0_var.startswith(b"HDR1L1000032"))
        enc_key_var = resp_l0_var[12:]
        self.assertEqual(len(enc_key_var), 32)

        # Decrypt under variant 1 and verify clear key length
        clear_key_var = self.hsm.lmk_engine.decrypt_under_lmk(enc_key_var, variant=1)
        self.assertEqual(len(clear_key_var), 32)

        # 2. Key Block LMK: Hash ID FF, Usage FF, Length 32 bytes, Format 04, Key Block Spec after #
        req_l0_kb = b"HDR1L0FFFF003204#63H0C00E00"
        resp_l0_kb = self.hsm.process_raw_message(req_l0_kb)
        self.assertTrue(resp_l0_kb.startswith(b"HDR1L100FFFF"))
        key_block_str = resp_l0_kb[12:].decode("ascii")

        hdr, clear_key_kb = TR31KeyBlock.unwrap(key_block_str, self.lmk)
        self.assertEqual(hdr.key_usage, "63")
        self.assertEqual(hdr.algorithm, "H")
        self.assertEqual(hdr.mode_of_use, "C")
        self.assertEqual(len(clear_key_kb), 32)

    def test_l0_error_codes(self):
        """Test L0 validation error codes."""
        # Key format invalid -> Error 07
        resp = self.hsm.process_raw_message(b"HDR1L00603003299")
        self.assertTrue(resp.startswith(b"HDR1L107"))

        # Hash ID invalid for variant -> Error 05
        resp = self.hsm.process_raw_message(b"HDR1L09903003200")
        self.assertTrue(resp.startswith(b"HDR1L105"))

        # Key length < L/2 (for SHA-256, L=32, L/2=16; try length 10) -> Error 04
        resp = self.hsm.process_raw_message(b"HDR1L00603001000")
        self.assertTrue(resp.startswith(b"HDR1L104"))

    def test_lq_and_ls_with_variant_key(self):
        """Test LQ (Generate HMAC) and LS (Verify HMAC) with Variant key across algorithms."""
        algos = [
            ("01", 20, hashlib.sha1),
            ("05", 28, hashlib.sha224),
            ("06", 32, hashlib.sha256),
            ("07", 48, hashlib.sha384),
            ("08", 64, hashlib.sha512),
        ]
        message_data = b"Payment Transaction Data 1234567890"
        data_len_str = f"{len(message_data):05d}".encode("ascii")

        for hash_id, digest_len, hash_fn in algos:
            # Generate key with L0
            req_l0 = f"HDR1L0{hash_id}03{digest_len:04d}00".encode("ascii")
            resp_l0 = self.hsm.process_raw_message(req_l0)
            self.assertTrue(resp_l0.startswith(b"HDR1L100"))
            enc_key = resp_l0[12:]

            # Generate HMAC with LQ
            hmac_len_str = f"{digest_len:04d}".encode("ascii")
            lq_payload = (
                hash_id.encode("ascii")
                + hmac_len_str
                + b"00"
                + f"{len(enc_key):04d}".encode("ascii")
                + enc_key
                + b";"
                + data_len_str
                + message_data
            )
            resp_lq = self.hsm.process_raw_message(b"HDR1LQ" + lq_payload)
            self.assertTrue(resp_lq.startswith(b"HDR1LR00" + hmac_len_str))
            generated_hmac = resp_lq[12:]
            self.assertEqual(len(generated_hmac), digest_len)

            # Verify using python's hmac independently
            clear_key = self.hsm.lmk_engine.decrypt_under_lmk(enc_key, variant=1)[:digest_len]
            expected_hmac = hmac.new(clear_key, message_data, hash_fn).digest()
            self.assertEqual(generated_hmac, expected_hmac)

            # Verify HMAC with LS (Success -> LT00)
            ls_payload = (
                hash_id.encode("ascii")
                + hmac_len_str
                + generated_hmac
                + b"00"
                + f"{len(enc_key):04d}".encode("ascii")
                + enc_key
                + b";"
                + data_len_str
                + message_data
            )
            resp_ls = self.hsm.process_raw_message(b"HDR1LS" + ls_payload)
            self.assertEqual(resp_ls, b"HDR1LT00")

            # Verify HMAC with LS (Tampered data -> Failure -> LT01)
            tampered_data = b"Payment Transaction Data CORRUPTED!"
            tampered_len_str = f"{len(tampered_data):05d}".encode("ascii")
            ls_tampered = (
                hash_id.encode("ascii")
                + hmac_len_str
                + generated_hmac
                + b"00"
                + f"{len(enc_key):04d}".encode("ascii")
                + enc_key
                + b";"
                + tampered_len_str
                + tampered_data
            )
            resp_ls_fail = self.hsm.process_raw_message(b"HDR1LS" + ls_tampered)
            self.assertEqual(resp_ls_fail, b"HDR1LT01")

    def test_lq_and_ls_with_keyblock(self):
        """Test LQ/LR and LS/LT using TR-31 Key Block HMAC keys."""
        # Generate SHA-256 Key Block key
        req_l0 = b"HDR1L0FFFF003204#63H0C00E00"
        resp_l0 = self.hsm.process_raw_message(req_l0)
        self.assertTrue(resp_l0.startswith(b"HDR1L100FFFF"))
        key_block_bytes = resp_l0[12:]

        message_data = b"Hello, Thales payShield 10K HMAC!"
        data_len_str = f"{len(message_data):05d}".encode("ascii")
        hmac_len_str = b"0032"

        # Generate HMAC with LQ
        lq_payload = (
            b"FF"
            + hmac_len_str
            + b"04FFFF"
            + key_block_bytes
            + data_len_str
            + message_data
        )
        resp_lq = self.hsm.process_raw_message(b"HDR1LQ" + lq_payload)
        self.assertTrue(resp_lq.startswith(b"HDR1LR000032"))
        hmac_bytes = resp_lq[12:]
        self.assertEqual(len(hmac_bytes), 32)

        # Verify HMAC with LS
        ls_payload = (
            b"FF"
            + hmac_len_str
            + hmac_bytes
            + b"04FFFF"
            + key_block_bytes
            + data_len_str
            + message_data
        )
        resp_ls = self.hsm.process_raw_message(b"HDR1LS" + ls_payload)
        self.assertEqual(resp_ls, b"HDR1LT00")

    def test_lq_truncation_and_length_error(self):
        """Test LQ HMAC length truncation (L/2 <= t <= L) and error 04 if t < L/2."""
        # Generate SHA-256 key (L = 32, minimum allowed t = 16)
        req_l0 = b"HDR1L00603003200"
        resp_l0 = self.hsm.process_raw_message(req_l0)
        enc_key = resp_l0[12:]

        message = b"Truncation test"
        data_len_str = f"{len(message):05d}".encode("ascii")

        # Request truncated HMAC of 16 bytes (valid since 16 >= 32//2)
        lq_valid = (
            b"06001600"
            + f"{len(enc_key):04d}".encode("ascii")
            + enc_key
            + b";"
            + data_len_str
            + message
        )
        resp_lq = self.hsm.process_raw_message(b"HDR1LQ" + lq_valid)
        self.assertTrue(resp_lq.startswith(b"HDR1LR000016"))
        self.assertEqual(len(resp_lq[12:]), 16)

        # Request truncated HMAC of 10 bytes (invalid since 10 < 16) -> Error 04
        lq_invalid = (
            b"06001000"
            + f"{len(enc_key):04d}".encode("ascii")
            + enc_key
            + b";"
            + data_len_str
            + message
        )
        resp_lq_err = self.hsm.process_raw_message(b"HDR1LQ" + lq_invalid)
        self.assertTrue(resp_lq_err.startswith(b"HDR1LR04"))

    def test_lq_comprehensive_error_codes(self):
        """Test all error codes for LQ: 15 (input data), 07 (key format), 05 (hash id), 04 (hmac len), A6 (usage), A8 (mode), 10 (keyblock MAC)."""
        # 1. Payload too short (< 17 bytes) -> Error 15
        r_short = self.hsm.process_raw_message(b"HDR1LQ06003200")
        self.assertTrue(r_short.startswith(b"HDR1LR15"))

        # 2. Invalid key format ('99') -> Error 07
        r_fmt = self.hsm.process_raw_message(b"HDR1LQ060032990032" + b"0" * 32 + b";00004TEST")
        self.assertTrue(r_fmt.startswith(b"HDR1LR07"))

        # 3. Invalid hash ID ('99') for Variant key -> Error 05
        r_hash = self.hsm.process_raw_message(b"HDR1LQ990032000032" + b"0" * 32 + b";00004TEST")
        self.assertTrue(r_hash.startswith(b"HDR1LR05"))

        # 4. Missing semicolon delimiter in Variant key payload -> Error 15
        r_semicolon = self.hsm.process_raw_message(b"HDR1LQ060032000032" + b"0" * 32 + b"00004TEST")
        self.assertTrue(r_semicolon.startswith(b"HDR1LR15"))

        # 5. HMAC length too large (> 32 for SHA-256) -> Error 04
        r_len_big = self.hsm.process_raw_message(b"HDR1LQ060033000032" + b"0" * 32 + b";00004TEST")
        self.assertTrue(r_len_big.startswith(b"HDR1LR04"))

        # 6. Key Block with invalid Key Usage ('C0' CVK instead of '61'..'65') -> Error A6
        raw_key = b"K" * 32
        hdr_c0 = TR31Header(version_id="1", key_length=128, key_usage="C0", algorithm="H", mode_of_use="C", key_version="00", exportability="E", optional_headers=b"", lmk_identifier="00")
        kb_c0 = TR31KeyBlock.wrap(raw_key, hdr_c0, self.lmk)
        r_usage = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + kb_c0 + b"00004TEST")
        self.assertTrue(r_usage.startswith(b"HDR1LRA6"))

        # 7. Key Block with invalid Mode of Use ('E' instead of C/G/N) -> Error A8
        hdr_e = TR31Header(version_id="1", key_length=128, key_usage="63", algorithm="H", mode_of_use="E", key_version="00", exportability="E", optional_headers=b"", lmk_identifier="00")
        kb_e = TR31KeyBlock.wrap(raw_key, hdr_e, self.lmk)
        r_mode = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + kb_e + b"00004TEST")
        self.assertTrue(r_mode.startswith(b"HDR1LRA8"))

        # 8. Corrupted Key Block (MAC mismatch) -> Error 10 (or 83)
        kb_corrupt = bytearray(kb_e)
        kb_corrupt[-2] = ord("0") if kb_corrupt[-2] != ord("0") else ord("1")
        r_corrupt = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + bytes(kb_corrupt) + b"00004TEST")
        self.assertTrue(r_corrupt.startswith(b"HDR1LR10") or r_corrupt.startswith(b"HDR1LR83"))

    def test_trailer_echo_in_lq_and_ls(self):
        """Test that trailer delimited by 0x19 is properly preserved and echoed."""
        req_l0 = b"HDR1L00603003200\x19TRAILER_L0"
        resp_l0 = self.hsm.process_raw_message(req_l0)
        self.assertTrue(resp_l0.endswith(b"\x19TRAILER_L0"))

        enc_key = resp_l0[12:-len(b"\x19TRAILER_L0")]
        message = b"Data with trailer"
        data_len_str = f"{len(message):05d}".encode("ascii")

        # LQ with trailer
        lq_req = (
            b"HDR1LQ06003200"
            + f"{len(enc_key):04d}".encode("ascii")
            + enc_key
            + b";"
            + data_len_str
            + message
            + b"\x19MY_HOST_TRAILER_123"
        )
        resp_lq = self.hsm.process_raw_message(lq_req)
        self.assertTrue(resp_lq.endswith(b"\x19MY_HOST_TRAILER_123"))

        hmac_bytes = resp_lq[12:-len(b"\x19MY_HOST_TRAILER_123")]

        # LS with trailer
        ls_req = (
            b"HDR1LS060032"
            + hmac_bytes
            + b"00"
            + f"{len(enc_key):04d}".encode("ascii")
            + enc_key
            + b";"
            + data_len_str
            + message
            + b"\x19MY_HOST_TRAILER_123"
        )
        resp_ls = self.hsm.process_raw_message(ls_req)
        self.assertEqual(resp_ls, b"HDR1LT00\x19MY_HOST_TRAILER_123")

    def test_lu_import_and_lw_export_under_zmk(self):
        """Test exporting HMAC key with LW and importing with LU under ZMK."""
        # 1. Generate a ZMK under LMK
        zmk_clear = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        enc_zmk = self.hsm.lmk_engine.encrypt_under_lmk(zmk_clear, variant=1)
        zmk_field = "U" + hexlify(enc_zmk).decode("ascii").upper()

        # 2. Generate an HMAC key under LMK (Key Block)
        resp_l0 = self.hsm.process_raw_message(b"HDR1L0FFFF003204#63H0C00E00")
        kb_lmk = resp_l0[12:]

        # 3. Export HMAC key under ZMK using LW (Transport Format 01 - PKCS#11 ECB)
        lw_req = (
            b"HDR1LW"
            + zmk_field.encode("ascii")
            + b"04"
            + b"01"
            + b"FFFF"
            + kb_lmk
        )
        resp_lw = self.hsm.process_raw_message(lw_req)
        self.assertTrue(resp_lw.startswith(b"HDR1LX00"))
        payload_lx = resp_lw[8:]
        key_zmk_len = int(payload_lx[:4].decode("ascii"))
        enc_key_zmk = payload_lx[4:4 + key_zmk_len]
        rem_meta = payload_lx[4 + key_zmk_len:]
        hash_id = rem_meta[:2].decode("ascii")
        usage = rem_meta[2:4].decode("ascii")
        orig_len = int(rem_meta[4:8].decode("ascii"))

        self.assertEqual(hash_id, "06")  # SHA-256
        self.assertEqual(orig_len, 32)

        # 4. Import HMAC key back with LU under ZMK to a new Key Block under LMK
        lu_req = (
            b"HDR1LU"
            + zmk_field.encode("ascii")
            + f"{key_zmk_len:04d}".encode("ascii")
            + enc_key_zmk
            + b";"
            + b"01"
            + b"04"
            + rem_meta
        )
        resp_lu = self.hsm.process_raw_message(lu_req)
        self.assertTrue(resp_lu.startswith(b"HDR1LV00FFFF"))
        imported_kb = resp_lu[12:]

        # 5. Verify that both keys produce the exact same HMAC tag
        test_data = b"Verify LU/LW roundtrip compatibility"
        data_len = f"{len(test_data):05d}".encode("ascii")

        lq1 = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + kb_lmk + data_len + test_data)
        lq2 = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + imported_kb + data_len + test_data)

        self.assertEqual(lq1, lq2)
        self.assertTrue(lq1.startswith(b"HDR1LR000032"))

    def test_ly_translate_hmac_key_variant_to_keyblock(self):
        """Test LY translating an HMAC key from Variant format (00) to Key Block (04)."""
        # Generate Variant HMAC key
        resp_l0 = self.hsm.process_raw_message(b"HDR1L00603003200")
        enc_key_var = resp_l0[12:]

        # Translate with LY: Input Format 00, Output Format 04, Length 0032, Key, # Spec
        ly_req = (
            b"HDR1LY00040032"
            + enc_key_var
            + b"#63H0C00E00"
        )
        resp_ly = self.hsm.process_raw_message(ly_req)
        self.assertTrue(resp_ly.startswith(b"HDR1LZ00FFFF"))
        translated_kb = resp_ly[12:]

        # Verify that original Variant key and translated Key Block key yield identical HMAC
        test_msg = b"Cross-format migration validation test"
        msg_len = f"{len(test_msg):05d}".encode("ascii")

        lq_var = self.hsm.process_raw_message(b"HDR1LQ060032000032" + enc_key_var + b";" + msg_len + test_msg)
        lq_kb = self.hsm.process_raw_message(b"HDR1LQFF003204FFFF" + translated_kb + msg_len + test_msg)

        self.assertEqual(lq_var, lq_kb)
        self.assertTrue(lq_var.startswith(b"HDR1LR000032"))

    def test_bu_hmac_kcv_generation(self):
        """Test BU generating KCV for HMAC keys per Section 12 (HMAC on 0-byte message)."""
        # 1. Test Key Block HMAC Key: Usage 63 (SHA-256)
        resp_l0 = self.hsm.process_raw_message(b"HDR1L0FFFF003204#63H0C00E00")
        kb_str = resp_l0[12:].decode("ascii")
        _, raw_key = TR31KeyBlock.unwrap(kb_str, self.lmk)

        # Expected KCV: leftmost 6 hex characters of HMAC-SHA256 over 0-length message
        expected_kcv = hmac.new(raw_key, b"", hashlib.sha256).hexdigest()[:6].upper()

        bu_req = f"HDR1BU000S{kb_str}".encode("ascii")
        resp_bu = self.hsm.process_raw_message(bu_req)
        self.assertEqual(resp_bu, b"HDR1BV00" + expected_kcv.encode("ascii"))

        # 2. Test Variant HMAC Key: Type 063 (SHA-256)
        resp_l0_var = self.hsm.process_raw_message(b"HDR1L00603003200")
        enc_key_var = resp_l0_var[12:]
        raw_key_var = self.hsm.lmk_engine.decrypt_under_lmk(enc_key_var, variant=1)
        expected_kcv_var = hmac.new(raw_key_var, b"", hashlib.sha256).hexdigest()[:6].upper()

        bu_var_req = b"HDR1BU063U" + hexlify(enc_key_var).upper()
        resp_bu_var = self.hsm.process_raw_message(bu_var_req)
        self.assertEqual(resp_bu_var, b"HDR1BV00" + expected_kcv_var.encode("ascii"))

    def test_hsm_get_response_legacy_compatibility(self):
        """Test HSM.get_response dispatching DummyMessage instances for LQ, LS, L0."""
        # L0 via DummyMessage
        msg_l0 = DummyMessage(b"0603003200")
        msg_l0.command_code = b"L0"
        msg_l0.get_command_code = lambda: b"L0"
        resp_l0 = self.hsm.get_response(msg_l0)
        self.assertEqual(resp_l0.fields["Response Code"], b"L1")
        self.assertEqual(resp_l0.fields["Error Code"], b"00")
        enc_key = resp_l0.fields["Payload"][4:]

        # LQ via DummyMessage
        msg_data = b"012345"
        data_len = f"{len(msg_data):05d}".encode("ascii")
        lq_data = b"060032000032" + enc_key + b";" + data_len + msg_data
        msg_lq = LQ(lq_data)
        resp_lq = self.hsm.get_response(msg_lq)
        self.assertEqual(resp_lq.fields["Response Code"], b"LR")
        self.assertEqual(resp_lq.fields["Error Code"], b"00")
        hmac_tag = resp_lq.fields["Payload"][4:]
        self.assertEqual(len(hmac_tag), 32)

        # LS via DummyMessage
        ls_data = b"060032" + hmac_tag + b"000032" + enc_key + b";" + data_len + msg_data
        msg_ls = LS(ls_data)
        resp_ls = self.hsm.get_response(msg_ls)
        self.assertEqual(resp_ls.fields["Response Code"], b"LT")
        self.assertEqual(resp_ls.fields["Error Code"], b"00")

    def test_live_tcp_socket_hmac_commands(self):
        """End-to-end socket client test verifying L0, LQ, LS, BU over live TCP connection."""
        import socket
        import struct
        from pythales.hsm import PyThalesHSM

        server = PyThalesHSM(header=b"HDR1", port=0)
        server.start_server(host="127.0.0.1", port=0, background=True)
        bound_port = server._async_server._server.sockets[0].getsockname()[1]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", bound_port))

        def send_framed(payload: bytes) -> bytes:
            msg = b"HDR1" + payload
            sock.sendall(struct.pack("!H", len(msg)) + msg)
            len_bytes = sock.recv(2)
            resp_len = struct.unpack("!H", len_bytes)[0]
            resp = b""
            while len(resp) < resp_len:
                chunk = sock.recv(resp_len - len(resp))
                if not chunk:
                    break
                resp += chunk
            self.assertTrue(resp.startswith(b"HDR1"))
            return resp[4:]

        try:
            # 1. L0 Generate HMAC Key
            resp_l0 = send_framed(b"L00603003200")
            self.assertTrue(resp_l0.startswith(b"L1000032"))
            enc_key = resp_l0[8:]
            self.assertEqual(len(enc_key), 32)

            # 2. LQ Generate HMAC
            msg = b"Live TCP HMAC Test"
            lq_req = b"LQ060032000032" + enc_key + b";" + f"{len(msg):05d}".encode("ascii") + msg
            resp_lq = send_framed(lq_req)
            self.assertTrue(resp_lq.startswith(b"LR000032"))
            hmac_tag = resp_lq[8:]
            self.assertEqual(len(hmac_tag), 32)

            # 3. LS Verify HMAC
            ls_req = b"LS060032" + hmac_tag + b"000032" + enc_key + b";" + f"{len(msg):05d}".encode("ascii") + msg
            resp_ls = send_framed(ls_req)
            self.assertEqual(resp_ls, b"LT00")

            # 4. BU KCV
            bu_req = b"BU063U" + hexlify(enc_key).upper()
            resp_bu = send_framed(bu_req)
            self.assertTrue(resp_bu.startswith(b"BV00"))

            # 5. LY Translate Variant to Key Block
            ly_req = b"LY00040032" + enc_key + b"#63H0C00E00"
            resp_ly = send_framed(ly_req)
            self.assertTrue(resp_ly.startswith(b"LZ00FFFF"))
            kb_lmk = resp_ly[8:]

            # 6. LW Export HMAC Key under ZMK
            zmk_clear = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
            enc_zmk = server.lmk_engine.encrypt_under_lmk(zmk_clear, variant=1)
            zmk_field = "U" + hexlify(enc_zmk).decode("ascii").upper()

            lw_req = b"LW" + zmk_field.encode("ascii") + b"0401FFFF" + kb_lmk
            resp_lw = send_framed(lw_req)
            self.assertTrue(resp_lw.startswith(b"LX00"))
            payload_lx = resp_lw[4:]
            key_zmk_len = int(payload_lx[:4].decode("ascii"))
            enc_key_zmk = payload_lx[4:4 + key_zmk_len]
            rem_meta = payload_lx[4 + key_zmk_len:]

            # 7. LU Import HMAC Key under ZMK
            lu_req = b"LU" + zmk_field.encode("ascii") + f"{key_zmk_len:04d}".encode("ascii") + enc_key_zmk + b";0104" + rem_meta
            resp_lu = send_framed(lu_req)
            self.assertTrue(resp_lu.startswith(b"LV00FFFF"))
            imported_kb = resp_lu[8:]

            # 8. Verify imported key block generates identical HMAC via LQ
            lq_kb = send_framed(b"LQFF003204FFFF" + imported_kb + f"{len(msg):05d}".encode("ascii") + msg)
            self.assertEqual(lq_kb, b"LR000032" + hmac_tag)
        finally:
            sock.close()
            server.stop_server()


if __name__ == "__main__":
    unittest.main()

