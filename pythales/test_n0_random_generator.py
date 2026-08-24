"""
Unit and integration tests for Host Command N0 / Response N1: Generate a Random Value.
Root of Trust: Thales payShield 10K Core Host Commands Manual (Section 8.2, Pages 504-505).
"""

import os
import socket
import struct
import unittest
from pythales.hsm import PyThalesHSM, HSM, N0
from pythales.core.frame import MessageFraming, CommandFrame, ResponseFrame
from pythales.core.errors import ErrorCodes


class TestN0GenerateRandomValue(unittest.TestCase):
    def setUp(self):
        self.hsm = PyThalesHSM()

    def test_n0_valid_lengths_success(self):
        """Test valid length requests: 1, 8, 16, 32, 64, 128, 256 bytes."""
        for length in [1, 8, 16, 32, 64, 128, 256]:
            length_str = f"{length:03d}".encode("ascii")
            req = b"N0" + length_str
            resp = self.hsm.process_raw_message(req)
            self.assertEqual(resp[:2], b"N1")
            self.assertEqual(resp[2:4], b"00")
            random_data = resp[4:]
            self.assertEqual(len(random_data), length)

    def test_n0_randomness_entropy(self):
        """Test that two consecutive generations produce different bytes."""
        req = b"N0032"
        resp1 = self.hsm.process_raw_message(req)
        resp2 = self.hsm.process_raw_message(req)
        self.assertEqual(resp1[:4], b"N100")
        self.assertEqual(resp2[:4], b"N100")
        self.assertEqual(len(resp1[4:]), 32)
        self.assertEqual(len(resp2[4:]), 32)
        self.assertNotEqual(resp1[4:], resp2[4:])

    def test_n0_out_of_range_lengths_error_01(self):
        """Test invalid random value lengths outside 001-256 return error 01."""
        for invalid_len in ["000", "257", "300", "500", "999"]:
            req = f"N0{invalid_len}".encode("ascii")
            resp = self.hsm.process_raw_message(req)
            self.assertEqual(resp[:2], b"N1")
            self.assertEqual(resp[2:4], b"01")
            self.assertEqual(resp[4:], b"")

    def test_n0_invalid_input_data_error_15(self):
        """Test malformed request lengths (non-numeric, wrong length) return error 15."""
        invalid_payloads = [
            b"N0",          # Missing length
            b"N01",         # 1 digit
            b"N016",        # 2 digits
            b"N00016",      # 4 digits
            b"N001A",       # Non-numeric
            b"N0ABC",       # Non-numeric
            b"N0-05",       # Non-numeric
        ]
        for req in invalid_payloads:
            resp = self.hsm.process_raw_message(req)
            self.assertEqual(resp[:2], b"N1")
            self.assertEqual(resp[2:4], b"15")
            self.assertEqual(resp[4:], b"")

    def test_n0_command_disabled_error_68(self):
        """Test that disabled command returns error 68."""
        self.hsm.command_n0_disabled = True
        req = b"N0016"
        resp = self.hsm.process_raw_message(req)
        self.assertEqual(resp[:2], b"N1")
        self.assertEqual(resp[2:4], b"68")
        self.assertEqual(resp[4:], b"")

    def test_n0_with_message_header(self):
        """Test N0 with 4-byte message header echoing."""
        hsm_with_header = PyThalesHSM(header="HDR1")
        req = b"HDR1N0016"
        resp = hsm_with_header.process_raw_message(req)
        self.assertEqual(resp[:4], b"HDR1")
        self.assertEqual(resp[4:6], b"N1")
        self.assertEqual(resp[6:8], b"00")
        self.assertEqual(len(resp[8:]), 16)

    def test_n0_with_delimiter_and_trailer(self):
        """Test N0 with 0x19 delimiter and message trailer."""
        hsm_with_header = PyThalesHSM(header="HDR1")
        trailer = b"TRAILER123"
        req = b"HDR1N0016\x19" + trailer
        resp = hsm_with_header.process_raw_message(req)
        self.assertTrue(resp.startswith(b"HDR1N100"))
        # Payload after HDR1N100 is 16 bytes + \x19 + trailer
        body = resp[8:]
        self.assertEqual(len(body), 16 + 1 + len(trailer))
        random_bytes = body[:16]
        delimiter = body[16:17]
        echoed_trailer = body[17:]
        self.assertEqual(delimiter, b"\x19")
        self.assertEqual(echoed_trailer, trailer)

    def test_n0_with_delimiter_and_trailer_on_error(self):
        """Test N0 with error retains delimiter and trailer in response."""
        hsm_with_header = PyThalesHSM(header="HDR1")
        trailer = b"TRAILER_ERR"
        req = b"HDR1N0999\x19" + trailer
        resp = hsm_with_header.process_raw_message(req)
        self.assertEqual(resp, b"HDR1N101\x19" + trailer)

    def test_n0_execute_command_tcp_framing(self):
        """Test execute_command returns 2-byte length prefixed response."""
        raw_req = b"N0032"
        framed_req = struct.pack("!H", len(raw_req)) + raw_req
        framed_resp = self.hsm.execute_command(framed_req)
        resp_len = struct.unpack("!H", framed_resp[:2])[0]
        resp_body = framed_resp[2:]
        self.assertEqual(len(resp_body), resp_len)
        self.assertEqual(resp_body[:4], b"N100")
        self.assertEqual(len(resp_body[4:]), 32)

    def test_n0_legacy_hsm_dummy_message(self):
        """Test backward-compatible HSM.get_response(N0(...)) flow."""
        hsm = HSM()
        req_msg = N0(b"016")
        resp_msg = hsm.get_response(req_msg)
        self.assertEqual(resp_msg.get_command_code(), "N1")
        self.assertEqual(resp_msg.get("Error Code"), b"00")
        rand_val = resp_msg.get("Random Value")
        self.assertEqual(len(rand_val), 16)

    def test_n0_over_async_tcp_server(self):
        """Test N0 command over real TCP socket connection."""
        server_hsm = PyThalesHSM(port=1655)
        server_hsm.start_server(port=1655, background=True)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(("127.0.0.1", 1655))
            try:
                # Send framed request: N0048 (48 bytes)
                req_body = b"N0048"
                sock.sendall(struct.pack("!H", len(req_body)) + req_body)
                
                # Read response length prefix
                len_bytes = sock.recv(2)
                self.assertEqual(len(len_bytes), 2)
                resp_len = struct.unpack("!H", len_bytes)[0]
                
                # Read response body
                resp_body = b""
                while len(resp_body) < resp_len:
                    chunk = sock.recv(resp_len - len(resp_body))
                    if not chunk:
                        break
                    resp_body += chunk

                self.assertEqual(len(resp_body), resp_len)
                self.assertEqual(resp_body[:2], b"N1")
                self.assertEqual(resp_body[2:4], b"00")
                self.assertEqual(len(resp_body[4:]), 48)
            finally:
                sock.close()
        finally:
            server_hsm.stop_server()


if __name__ == "__main__":
    unittest.main()
