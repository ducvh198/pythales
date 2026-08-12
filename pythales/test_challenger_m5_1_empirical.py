"""
Empirical Verification & Socket Stress Test Suite for Milestone M5 (challenger_m5_1).
Target: AsyncHSMServer, PyThalesHSM facade, TCP framing, Header Mirroring, Error Code Truncation Rule.
"""

import socket
import struct
import time
import pytest
import string
from pythales.hsm import PyThalesHSM
from pythales.server.async_server import AsyncHSMServer
from pythales.core.frame import MessageFraming, CommandFrame, ResponseFrame


EMPIRICAL_PORT = 1585
HEADER_EMPIRICAL_PORT = 1586
LIFECYCLE_PORT = 1587


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a TCP socket stream."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed while attempting to read {n} bytes (read {len(data)})")
        data += chunk
    return data


def send_receive_tcp_framed(sock: socket.socket, payload: bytes) -> bytes:
    """Send payload with 2-byte big-endian prefix and receive response frame."""
    frame = struct.pack("!H", len(payload)) + payload
    sock.sendall(frame)
    len_bytes = recv_exact(sock, 2)
    resp_len = struct.unpack("!H", len_bytes)[0]
    return recv_exact(sock, resp_len)


# ============================================================================
# TEST CASES
# ============================================================================

def test_tcp_2byte_length_prefix_standard_and_fragmented():
    """
    1. Verify 2-byte big-endian TCP length prefixes.
    - Test standard framed send/recv.
    - Test fragmented socket sends (sending 1 byte of length prefix, pausing, sending body in 1-byte chunks).
    """
    hsm = PyThalesHSM(port=EMPIRICAL_PORT)
    hsm.start_server(host="127.0.0.1", port=EMPIRICAL_PORT, background=True)
    time.sleep(0.15)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", EMPIRICAL_PORT))

        # Standard send
        req = b"NC"
        resp = send_receive_tcp_framed(sock, req)
        assert resp.startswith(b"ND00"), f"Expected ND00, got {resp!r}"

        # Fragmented send (1 byte length prefix, 1 byte length prefix, then 1 byte chunks of payload)
        msg = b"NOFRAGMENT_TEST"
        framed = struct.pack("!H", len(msg)) + msg

        # Send byte by byte with micro-sleeps to force TCP fragmentation
        for b in framed:
            sock.sendall(bytes([b]))
            time.sleep(0.005)

        len_bytes = recv_exact(sock, 2)
        resp_len = struct.unpack("!H", len_bytes)[0]
        resp_payload = recv_exact(sock, resp_len)

        assert resp_payload.startswith(b"NP00"), f"Expected NP00, got {resp_payload!r}"
        assert resp_payload[4:] == b"FRAGMENT_TEST", f"Expected echoed payload, got {resp_payload[4:]!r}"

        sock.close()
    finally:
        hsm.stop_server()
        time.sleep(0.1)


def test_tcp_multi_message_stream():
    """
    Verify multiple messages piped back-to-back over a single TCP connection.
    """
    hsm = PyThalesHSM(port=EMPIRICAL_PORT)
    hsm.start_server(host="127.0.0.1", port=EMPIRICAL_PORT, background=True)
    time.sleep(0.15)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", EMPIRICAL_PORT))

        # Send 5 commands over same socket stream
        for i in range(5):
            echo_str = f"STREAM_MSG_{i}".encode("ascii")
            req = b"NO" + echo_str
            resp = send_receive_tcp_framed(sock, req)
            assert resp == b"NP00" + echo_str, f"Iteration {i} failed: {resp!r}"

        sock.close()
    finally:
        hsm.stop_server()
        time.sleep(0.1)


def test_2byte_header_echoing_success_and_error():
    """
    2. Verify 2-byte Header echoing over live TCP connection.
    - Test that 2-byte request header is echoed on success (ND00).
    - Test that 2-byte request header is echoed on error response (e.g. XY15).
    """
    header = b"H1"
    hsm = PyThalesHSM(header=header, port=HEADER_EMPIRICAL_PORT)
    hsm.start_server(host="127.0.0.1", port=HEADER_EMPIRICAL_PORT, header_length=2, background=True)
    time.sleep(0.15)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", HEADER_EMPIRICAL_PORT))

        # Test success response header echoing
        req_body = header + b"NC"
        resp = send_receive_tcp_framed(sock, req_body)
        assert resp.startswith(b"H1ND00"), f"Expected H1ND00 prefix, got {resp!r}"

        # Test error response header echoing
        invalid_req_body = header + b"XX"
        err_resp = send_receive_tcp_framed(sock, invalid_req_body)
        assert err_resp.startswith(b"H1"), f"Expected H1 header on error response, got {err_resp!r}"
        assert err_resp[2:4] in (b"XY", b"XX"), f"Expected XY/XX response code on error, got {err_resp[2:4]!r}"
        assert err_resp[4:6] != b"00", f"Expected error code != 00, got {err_resp[4:6]!r}"
        # Payload after error code MUST be truncated
        assert len(err_resp) == 6, f"Expected total error response length of 6 (2-byte header + 2-byte response code + 2-byte error code), got {len(err_resp)}"

        sock.close()
    finally:
        hsm.stop_server()
        time.sleep(0.1)


def test_payshield_error_code_truncation_rule_comprehensive():
    """
    3. Verify PayShield Error Code Truncation Rule:
    When Error Code != '00', response payload MUST be truncated after the 2-byte error code.
    No extra fields, error description, or parameters should follow the 2-byte error code.
    """
    hsm = PyThalesHSM(port=EMPIRICAL_PORT)
    hsm.start_server(host="127.0.0.1", port=EMPIRICAL_PORT, background=True)
    time.sleep(0.15)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", EMPIRICAL_PORT))

        # Scenario A: Unknown Command Code -> XX15 (Invalid command)
        resp_a = send_receive_tcp_framed(sock, b"INVALID_CMD_99")
        resp_code_a = resp_a[:2].decode("ascii")
        err_code_a = resp_a[2:4].decode("ascii")
        payload_a = resp_a[4:]
        assert err_code_a != "00", f"Expected error code != 00, got {err_code_a!r}"
        assert len(payload_a) == 0, f"Error Truncation Violation: expected 0 bytes payload after error code, got {payload_a!r} (len {len(payload_a)})"

        # Scenario B: Invalid parameters for A0 command (e.g. invalid key type '999')
        resp_b = send_receive_tcp_framed(sock, b"A099900U")
        resp_code_b = resp_b[:2].decode("ascii")
        err_code_b = resp_b[2:4].decode("ascii")
        payload_b = resp_b[4:]
        assert resp_code_b == "A1", f"Expected A1 response code, got {resp_code_b!r}"
        assert err_code_b != "00", f"Expected error code != 00, got {err_code_b!r}"
        assert len(payload_b) == 0, f"Error Truncation Violation: expected 0 bytes payload after error code, got {payload_b!r}"

        # Scenario C: Valid command (NC) -> Error Code '00', Payload MUST NOT be truncated!
        resp_c = send_receive_tcp_framed(sock, b"NC")
        err_code_c = resp_c[2:4].decode("ascii")
        payload_c = resp_c[4:]
        assert err_code_c == "00", f"Expected 00 error code, got {err_code_c!r}"
        assert len(payload_c) > 0, f"Success response should contain payload, got length 0"

        sock.close()
    finally:
        hsm.stop_server()
        time.sleep(0.1)


def test_pythales_hsm_standalone_facade_and_lifecycle():
    """
    4. Verify Standalone PyThalesHSM facade execution and server lifecycle.
    - Standalone execute_command() in-memory execution.
    - start_server() and stop_server() lifecycle and is_server_running() status.
    """
    # Standalone in-memory execution
    hsm_standalone = PyThalesHSM()
    raw_req = b"NC"
    framed_resp = hsm_standalone.execute_command(raw_req)
    assert len(framed_resp) >= 6
    expected_len = struct.unpack("!H", framed_resp[:2])[0]
    assert expected_len == len(framed_resp) - 2
    assert framed_resp[2:6] == b"ND00"

    # Also test passing framed raw_req to execute_command
    req_with_len = struct.pack("!H", len(raw_req)) + raw_req
    framed_resp2 = hsm_standalone.execute_command(req_with_len)
    assert framed_resp2 == framed_resp

    # Lifecycle start/stop verification
    hsm_server = PyThalesHSM(port=LIFECYCLE_PORT)
    assert not hsm_server.is_server_running()

    hsm_server.start_server(host="127.0.0.1", port=LIFECYCLE_PORT, background=True)
    time.sleep(0.15)
    assert hsm_server.is_server_running()

    # Perform a TCP connection to verify active server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect(("127.0.0.1", LIFECYCLE_PORT))
    resp = send_receive_tcp_framed(sock, b"NOFACADE_TEST")
    assert resp == b"NP00FACADE_TEST"
    sock.close()

    hsm_server.stop_server()
    time.sleep(0.15)
    assert not hsm_server.is_server_running()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
