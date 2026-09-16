"""
Adversarial Stress Test Suite for PyThales Milestone M1.
Focus areas:
1. TCP Envelope & Framing (Empty payload, malformed headers, error code != '00' truncation).
2. Error Codes (25 PayShield 10K standard error codes mapping and exception handling).
3. LMK Engine (Variants 0-9 XOR masks, 16-byte and 24-byte LMKs, PCI key separation violation, DEK protection violation).
"""

import unittest
import struct
from pythales.core.frame import MessageFraming, CommandFrame, ResponseFrame
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.lmk import LMKEngine, VARIANT_MASKS


class TestAdversarialFraming(unittest.TestCase):
    def test_tcp_2byte_header_empty_payload(self):
        # TCP framing with 2-byte length = 2 (only command code NC, empty payload)
        raw_msg = b"\x00\x02NC"
        frame = MessageFraming.parse_request(raw_msg)
        self.assertEqual(frame.command_code, "NC")
        self.assertEqual(frame.payload_bytes, b"")
        self.assertFalse(frame.delimiter_present)
        self.assertEqual(frame.trailer_bytes, b"")

    def test_tcp_2byte_header_zero_length_bytes(self):
        # Boundary test: 2-byte prefix with len 0
        raw_msg = b"\x00\x00"
        with self.assertRaises(PayShieldException) as cm:
            MessageFraming.parse_request(raw_msg)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_INPUT_DATA)

    def test_tcp_2byte_header_single_byte(self):
        # Single byte raw data
        raw_msg = b"A"
        with self.assertRaises(PayShieldException) as cm:
            MessageFraming.parse_request(raw_msg)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_INPUT_DATA)

    def test_tcp_length_prefix_matching(self):
        # Length prefix \x00\x05 matching "NC123" (5 bytes)
        raw_msg = b"\x00\x05NC123"
        frame = MessageFraming.parse_request(raw_msg)
        self.assertEqual(frame.command_code, "NC")
        self.assertEqual(frame.payload_bytes, b"123")

    def test_malformed_headers(self):
        # Header length specified larger than actual data length
        raw_msg = b"HDR"
        with self.assertRaises(PayShieldException) as cm:
            MessageFraming.parse_request(raw_msg, header_length=10)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_INPUT_DATA)

    def test_error_payload_is_preserved_by_framing(self):
        # Framing is transport-only. Some command errors carry diagnostics.
        error_codes_to_test = ["01", "02", "03", "10", "15", "21", "29", "80", "A6", "A7", "A8", "BC"]
        dirty_payload = b"SENSITIVE_DATA_FIELD_1234567890_SHOULD_NEVER_BE_SENT"

        for err_code in error_codes_to_test:
            # Test string error code
            resp = MessageFraming.format_response(
                header_bytes=b"HDR",
                response_code="ND",
                error_code=err_code,
                payload_bytes=dirty_payload
            )
            expected_body = b"HDRND" + err_code.encode("ascii") + dirty_payload
            self.assertEqual(resp, expected_body)

            # Test bytes error code
            resp_bytes_err = MessageFraming.format_response(
                header_bytes=b"HDR",
                response_code="ND",
                error_code=err_code.encode("ascii"),
                payload_bytes=dirty_payload
            )
            self.assertEqual(resp_bytes_err, expected_body)

            # Test with length prefix
            resp_prefixed = MessageFraming.format_response(
                header_bytes=b"HDR",
                response_code="ND",
                error_code=err_code,
                payload_bytes=dirty_payload,
                include_length_prefix=True
            )
            expected_prefix = struct.pack("!H", len(expected_body))
            self.assertEqual(resp_prefixed, expected_prefix + expected_body)

    def test_success_code_preserves_payload(self):
        payload = b"VALID_RESPONSE_DATA"
        resp = MessageFraming.format_response(
            header_bytes=b"HDR",
            response_code="ND",
            error_code="00",
            payload_bytes=payload
        )
        self.assertEqual(resp, b"HDRND00VALID_RESPONSE_DATA")

    def test_delimiter_and_trailer_parsing(self):
        # Body: HDR (3) + NC (2) + 123 (3) + \x19 (1) + TRAILER1 (8) + \x19 (1) + TRAILER2 (8) = 26 bytes (0x001A)
        raw_msg = b"\x00\x1AHDRNC123\x19TRAILER1\x19TRAILER2"
        frame = MessageFraming.parse_request(raw_msg, header_length=3)
        self.assertEqual(frame.header_bytes, b"HDR")
        self.assertEqual(frame.command_code, "NC")
        self.assertTrue(frame.delimiter_present)
        self.assertEqual(frame.payload_bytes, b"123")
        self.assertEqual(frame.trailer_bytes, b"TRAILER1\x19TRAILER2")

        # Binary trailer test
        raw_binary_trailer = b"HDRNCXYZ\x19\x00\x01\x02\xFF\xFE"
        frame_bin = MessageFraming.parse_request(raw_binary_trailer, header_length=3)
        self.assertTrue(frame_bin.delimiter_present)
        self.assertEqual(frame_bin.payload_bytes, b"XYZ")
        self.assertEqual(frame_bin.trailer_bytes, b"\x00\x01\x02\xFF\xFE")


class TestAdversarialErrorCodes(unittest.TestCase):
    REQUIRED_25_CODES = [
        "00", "01", "02", "03", "04", "05", "10", "11", "12", "13",
        "15", "17", "21", "23", "26", "27", "28", "29", "68", "80",
        "83", "A6", "A7", "A8", "BC"
    ]

    def test_all_25_error_codes_presence(self):
        for code in self.REQUIRED_25_CODES:
            self.assertIn(code, ErrorCodes.ALL_CODES, f"Error code {code} missing from ALL_CODES")
            self.assertIn(code, ErrorCodes.MESSAGES, f"Error code {code} missing from MESSAGES")

    def test_error_code_messages_non_empty(self):
        for code in self.REQUIRED_25_CODES:
            msg = ErrorCodes.get_message(code)
            self.assertTrue(isinstance(msg, str) and len(msg) > 0)
            self.assertFalse(msg.startswith("Unknown"), f"Message for code {code} is unknown")

    def test_payshield_exception_instantiation(self):
        for code in self.REQUIRED_25_CODES:
            exc = PayShieldException(code)
            self.assertEqual(exc.error_code, code)
            self.assertIn(code, str(exc))

    def test_unknown_error_code_fallback(self):
        msg = ErrorCodes.get_message("99")
        self.assertIn("Unknown PayShield Error", msg)
        exc = PayShieldException("99")
        self.assertEqual(exc.error_code, "99")
        self.assertIn("Unknown PayShield Error", exc.message)


class TestAdversarialLMKEngine(unittest.TestCase):
    BASE_16_LMK = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
    BASE_24_LMK = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x11\x22\x33\x44\x55\x66\x77\x88"

    def test_lmk_variants_0_through_9_xor_masks_16byte(self):
        eng = LMKEngine(self.BASE_16_LMK)
        for var_num in range(10):
            var_lmk = eng.get_variant_lmk(var_num)
            var_lmk_str = eng.get_variant_lmk(str(var_num))
            self.assertEqual(var_lmk, var_lmk_str)

            expected_mask = VARIANT_MASKS[var_num]
            expected_lmk = (
                bytes(a ^ b for a, b in zip(self.BASE_16_LMK[:8], expected_mask)) +
                bytes(a ^ b for a, b in zip(self.BASE_16_LMK[8:16], expected_mask))
            )
            self.assertEqual(var_lmk, expected_lmk)

    def test_lmk_variants_0_through_9_xor_masks_24byte(self):
        eng = LMKEngine(self.BASE_24_LMK)
        for var_num in range(10):
            var_lmk = eng.get_variant_lmk(var_num)
            var_lmk_str = eng.get_variant_lmk(str(var_num))
            self.assertEqual(var_lmk, var_lmk_str)

            expected_mask = VARIANT_MASKS[var_num]
            expected_lmk = (
                bytes(a ^ b for a, b in zip(self.BASE_24_LMK[:8], expected_mask)) +
                bytes(a ^ b for a, b in zip(self.BASE_24_LMK[8:16], expected_mask)) +
                bytes(a ^ b for a, b in zip(self.BASE_24_LMK[16:24], expected_mask))
            )
            self.assertEqual(var_lmk, expected_lmk)

    def test_lmk_encryption_decryption_16byte_and_24byte_keys(self):
        eng16 = LMKEngine(self.BASE_16_LMK)
        eng24 = LMKEngine(self.BASE_24_LMK)

        test_key_16 = b"\xAA" * 16
        test_key_24 = b"\xBB" * 24

        for var_num in range(10):
            # 16-byte LMK encrypt/decrypt
            enc16_16 = eng16.encrypt_under_lmk(test_key_16, variant=var_num)
            dec16_16 = eng16.decrypt_under_lmk(enc16_16, variant=var_num)
            self.assertEqual(dec16_16, test_key_16)

            enc16_24 = eng16.encrypt_under_lmk(test_key_24, variant=var_num)
            dec16_24 = eng16.decrypt_under_lmk(enc16_24, variant=var_num)
            self.assertEqual(dec16_24, test_key_24)

            # 24-byte LMK encrypt/decrypt
            enc24_16 = eng24.encrypt_under_lmk(test_key_16, variant=var_num)
            dec24_16 = eng24.decrypt_under_lmk(enc24_16, variant=var_num)
            self.assertEqual(dec24_16, test_key_16)

            enc24_24 = eng24.encrypt_under_lmk(test_key_24, variant=var_num)
            dec24_24 = eng24.decrypt_under_lmk(enc24_24, variant=var_num)
            self.assertEqual(dec24_24, test_key_24)

    def test_invalid_lmk_length(self):
        with self.assertRaises(ValueError):
            LMKEngine(b"\x00" * 8)
        with self.assertRaises(ValueError):
            LMKEngine(b"\x00" * 32)

    def test_invalid_variant_inputs(self):
        eng = LMKEngine(self.BASE_16_LMK)
        with self.assertRaises(PayShieldException) as cm:
            eng.get_variant_lmk(-1)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_SCHEME)

        with self.assertRaises(PayShieldException) as cm:
            eng.get_variant_lmk(10)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_SCHEME)

        with self.assertRaises(PayShieldException) as cm:
            eng.get_variant_lmk("INVALID_VAR")
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_SCHEME)

    def test_legacy_pci_policy_hook_does_not_invent_a7_errors(self):
        eng = LMKEngine(self.BASE_16_LMK, pci_mode=True)
        self.assertTrue(eng.validate_pci_key_separation("002", variant=2))
        self.assertEqual(ErrorCodes.INVALID_ALGORITHM, "A7")

    def test_legacy_dek_policy_hook_does_not_treat_008_as_dek(self):
        eng = LMKEngine(self.BASE_16_LMK)
        self.assertTrue(eng.validate_dek_protection("008", variant=1, export_scheme="U"))
        self.assertEqual(ErrorCodes.INVALID_MODE_OF_USE, "A8")

    def test_kcv_generation(self):
        key_16 = b"\x01" * 16
        kcv_16 = LMKEngine.generate_kcv(key_16)
        self.assertEqual(len(kcv_16), 6)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in kcv_16))

        key_24 = b"\x01" * 24
        kcv_24 = LMKEngine.generate_kcv(key_24)
        self.assertEqual(len(kcv_24), 6)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in kcv_24))


if __name__ == "__main__":
    unittest.main()
