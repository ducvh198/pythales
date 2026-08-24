#!/usr/bin/env python3
"""
HSM Socket Client Test Verification Suite for pythales.

Connects to a pythales HSM server via TCP socket, tests PayShield commands:
- Diagnostics: NC/ND, Network Echo: NO/NP
- Key Management: A0/A1, BU/BV
- PIN Processing: CA/CB, DC/DD
- Card Verification: CW/CX, CY/CZ
- Data Protection: M0/M1, M2/M3, M6/M7
- EMV Processing: KQ/KR
- TCP Framing & Header Mirroring
- Error Code Truncation Rule

Supports both pytest execution (`pytest test_hsm_client.py`) and direct CLI execution (`python test_hsm_client.py`).
"""

import argparse
import os
import socket
import struct
import sys
import string
import time
import pytest

from pythales.hsm import PyThalesHSM


@pytest.fixture(scope="module", autouse=True)
def live_hsm_server():
    """
    Module-level pytest fixture to start an in-process AsyncHSMServer
    on the target port before running socket client tests.
    """
    host = os.environ.get("HSM_HOST", "127.0.0.1")
    configured_port = os.environ.get("HSM_PORT")
    port = int(configured_port) if configured_port is not None else 0
    hsm = PyThalesHSM(port=port)
    hsm.start_server(host=host, port=port, background=True)
    bound_port = hsm._async_server._server.sockets[0].getsockname()[1]
    previous_port = os.environ.get("HSM_PORT")
    os.environ["HSM_PORT"] = str(bound_port)
    try:
        yield hsm
    finally:
        hsm.stop_server()
        if previous_port is None:
            os.environ.pop("HSM_PORT", None)
        else:
            os.environ["HSM_PORT"] = previous_port


def get_client_socket(host=None, port=None):
    """Utility to create a connected TCP client socket."""
    if host is None:
        host = os.environ.get("HSM_HOST", "127.0.0.1")
    if port is None:
        port = int(os.environ.get("HSM_PORT", "1500"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    return sock


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed prematurely while waiting for data")
        data += chunk
    return data


def send_receive_framed(sock, header_bytes, command_payload_bytes):
    """
    Send a framed command over socket and receive framed response.

    Wire format:
    [2 bytes Length (big-endian uint16)] + [Header (0..N bytes)] + [Payload]
    """
    msg_body = header_bytes + command_payload_bytes
    msg_len = len(msg_body)
    framed_request = struct.pack("!H", msg_len) + msg_body

    sock.sendall(framed_request)

    len_prefix = recv_exact(sock, 2)
    resp_len = struct.unpack("!H", len_prefix)[0]

    resp_data = recv_exact(sock, resp_len)

    if header_bytes:
        if len(resp_data) < len(header_bytes) or not resp_data.startswith(header_bytes):
            raise ValueError(
                f"Header mismatch in server response. "
                f"Expected header prefix {header_bytes!r}, received response {resp_data!r}"
            )
        resp_payload = resp_data[len(header_bytes):]
    else:
        resp_payload = resp_data

    return resp_payload


def test_nc_diagnostics(sock=None, header_bytes=b""):
    """
    Test Case 1: Send NC (Diagnostics) command.
    Verify ND response code, 00 error code, LMK check value, firmware version.
    """
    print("\n--- Test Case 1: Send NC (Diagnostics) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        req_payload = b"NC"
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
        assert len(resp_payload) >= 4

        resp_code = resp_payload[:2].decode("utf-8", errors="replace")
        err_code = resp_payload[2:4].decode("utf-8", errors="replace")
        remaining = resp_payload[4:]

        assert resp_code == "ND"
        assert err_code == "00"
        assert len(remaining) >= 16

        lmk_cv = remaining[:16].decode("utf-8", errors="replace")
        firmware_ver = remaining[16:].decode("utf-8", errors="replace")

        assert all(c in string.hexdigits for c in lmk_cv)
        assert len(firmware_ver) > 0
        print("[PASS] Test Case 1 (NC Diagnostics) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_a0_generate_key(sock=None, header_bytes=b""):
    """
    Test Case 2: Send A0 (Generate Key) command.
    Verify A1 response code, 00 error code, U + 32-char hex key + 6-char KCV (39 chars total).
    """
    print("\n--- Test Case 2: Send A0 (Generate Key) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        req_payload = b"A00000U"
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
        assert len(resp_payload) >= 4

        resp_code = resp_payload[:2].decode("utf-8", errors="replace")
        err_code = resp_payload[2:4].decode("utf-8", errors="replace")
        key_payload = resp_payload[4:].decode("utf-8", errors="replace")

        assert resp_code == "A1"
        assert err_code == "00"
        assert len(key_payload) == 39
        assert key_payload.startswith("U")
        assert all(c in string.hexdigits for c in key_payload[1:])
        print("[PASS] Test Case 2 (A0 Generate Key) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_bu_key_check_value(sock=None, header_bytes=b""):
    """
    Test Case 3: Send BU (Generate KCV) command.
    Verify BV response code, 00 error code, KCV payload.
    """
    print("\n--- Test Case 3: Send BU (Generate KCV) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_resp = send_receive_framed(sock, header_bytes, b"A00000U")
        assert gen_resp.startswith(b"A100")
        key_str = gen_resp[4:4+33].decode("ascii")

        bu_req = f"BU000{key_str}".encode("ascii")
        bu_resp = send_receive_framed(sock, header_bytes, bu_req)
        assert bu_resp.startswith(b"BV00")
        kcv = bu_resp[4:].decode("ascii")
        assert len(kcv) >= 6
        assert all(c in string.hexdigits for c in kcv)
        print("[PASS] Test Case 3 (BU Generate KCV) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_no_echo(sock=None, header_bytes=b""):
    """
    Test Case 4: Send NO (Network Echo Test) command.
    Verify NP response code, 00 error code, identical payload.
    """
    print("\n--- Test Case 4: Send NO (Network Echo Test) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        req_payload = b"NOPAYSHIELD_ECHO_DATA_1234"
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
        resp_code = resp_payload[:2].decode("utf-8", errors="replace")
        err_code = resp_payload[2:4].decode("utf-8", errors="replace")
        echo_data = resp_payload[4:]

        assert resp_code == "NP"
        assert err_code == "00"
        assert echo_data == b"PAYSHIELD_ECHO_DATA_1234"
        print("[PASS] Test Case 4 (NO Network Echo) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_n0_generate_random(sock=None, header_bytes=b""):
    """
    Test Case: Send N0 (Generate a Random Value) command.
    Verify N1 response code, 00 error code, binary random payload length.
    """
    print("\n--- Test Case: Send N0 (Generate a Random Value) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        req_payload = b"N0032"
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
        resp_code = resp_payload[:2].decode("utf-8", errors="replace")
        err_code = resp_payload[2:4].decode("utf-8", errors="replace")
        random_bytes = resp_payload[4:]

        assert resp_code == "N1"
        assert err_code == "00"
        assert len(random_bytes) == 32
        print("[PASS] Test Case (N0 Generate Random Value) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_ca_translate_pin(sock=None, header_bytes=b""):
    """
    Test Case 5: Send CA (Translate PIN Block) command.
    Verify CB response code.
    """
    print("\n--- Test Case 5: Send CA (Translate PIN Block) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen1 = send_receive_framed(sock, header_bytes, b"A00001U")
        zpk1 = gen1[4:4+33].decode("ascii")
        gen2 = send_receive_framed(sock, header_bytes, b"A00001U")
        zpk2 = gen2[4:4+33].decode("ascii")

        ca_req = f"CA{zpk1}{zpk2}122B687AEFC34B1A890101001123456789".encode("ascii")
        ca_resp = send_receive_framed(sock, header_bytes, ca_req)
        assert ca_resp[:2] == b"CB"
        assert ca_resp[2:4] in (b"00", b"10", b"11", b"21", b"23", b"26")
        print("[PASS] Test Case 5 (CA Translate PIN) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_dc_verify_pin(sock=None, header_bytes=b""):
    """
    Test Case 6: Send DC (Verify PIN) command.
    Verify DD response code.
    """
    print("\n--- Test Case 6: Send DC (Verify PIN) Command ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_tpk = send_receive_framed(sock, header_bytes, b"A00002U")
        tpk = gen_tpk[4:4+33].decode("ascii")

        pvk = "1234567890ABCDEF1234567890ABCDEF"
        dc_req = f"DC{tpk}{pvk}2B687AEFC34B1A890100112345678911234".encode("ascii")
        dc_resp = send_receive_framed(sock, header_bytes, dc_req)
        assert dc_resp[:2] == b"DD"
        assert dc_resp[2:4] in (b"00", b"01", b"10", b"11", b"12", b"26", b"27", b"29")
        print("[PASS] Test Case 6 (DC Verify PIN) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_cvv_workflow(sock=None, header_bytes=b""):
    """
    Test Case 7: Send CW (Generate CVV) & CY (Verify CVV).
    Verify CX00 response and CZ00 verification response.
    """
    print("\n--- Test Case 7: Send CW (Generate CVV) & CY (Verify CVV) ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_cw = send_receive_framed(sock, header_bytes, b"A00003U")
        cvk_key = gen_cw[4:4+33].decode("ascii")

        cw_req = f"CW{cvk_key}4111111111111111;2512101".encode("ascii")
        cw_resp = send_receive_framed(sock, header_bytes, cw_req)
        assert cw_resp.startswith(b"CX00")

        cvv = cw_resp[4:].decode("ascii")

        cy_req = f"CY{cvk_key}{cvv}4111111111111111;2512101".encode("ascii")
        cy_resp = send_receive_framed(sock, header_bytes, cy_req)
        assert cy_resp == b"CZ00"
        print("[PASS] Test Case 7 (CW/CY CVV Workflow) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_m0_m2_data_encrypt(sock=None, header_bytes=b""):
    """
    Test Case 8: Send M0 (Encrypt Data) & M2 (Decrypt Data).
    Verify M100 and M300 roundtrip.
    """
    print("\n--- Test Case 8: Send M0 (Encrypt Data) & M2 (Decrypt Data) ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_dek = send_receive_framed(sock, header_bytes, b"A00008U")
        dek_key = gen_dek[4:4+33].decode("ascii")

        plaintext_hex = "504159534849454C44313233343536"
        m0_req = f"M0{dek_key}0000F{plaintext_hex}".encode("ascii")
        m0_resp = send_receive_framed(sock, header_bytes, m0_req)
        assert m0_resp.startswith(b"M100")

        enc_hex = m0_resp[4:].decode("ascii")

        len_hex = f"{len(enc_hex) // 2:04X}"
        m2_req = f"M2{dek_key}0{len_hex}{enc_hex}".encode("ascii")
        m2_resp = send_receive_framed(sock, header_bytes, m2_req)
        assert m2_resp.startswith(b"M300")

        dec_hex = m2_resp[4:].decode("ascii")
        assert dec_hex == plaintext_hex
        print("[PASS] Test Case 8 (M0/M2 Data Encryption) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_m6_generate_mac(sock=None, header_bytes=b""):
    """
    Test Case 9: Send M6 (Generate MAC).
    Verify M700 response and 16-hex MAC payload.
    """
    print("\n--- Test Case 9: Send M6 (Generate MAC) ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_tak = send_receive_framed(sock, header_bytes, b"A0000AU")
        tak = gen_tak[4:4+33].decode("ascii")

        plaintext_hex = "504159534849454C4431323334353637"
        m6_req = f"M6{tak}000010{plaintext_hex}".encode("ascii")
        m6_resp = send_receive_framed(sock, header_bytes, m6_req)
        assert m6_resp.startswith(b"M700")

        mac = m6_resp[4:].decode("ascii")
        assert len(mac) == 16
        assert all(c in string.hexdigits for c in mac)
        print("[PASS] Test Case 9 (M6 Generate MAC) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_kq_emv_arqc(sock=None, header_bytes=b""):
    """
    Test Case 10: Send KQ (EMV ARQC).
    Verify KR00 response and 16-hex ARQC payload.
    """
    print("\n--- Test Case 10: Send KQ (EMV ARQC) ---")
    close_at_end = False
    if sock is None:
        sock = get_client_socket()
        close_at_end = True
    try:
        gen_mdk = send_receive_framed(sock, header_bytes, b"A00000U")
        mdk = gen_mdk[4:4+33].decode("ascii")

        kq_req = f"KQ1{mdk}4111111111111111;0100010010504159534849454C44313233343536".encode("ascii")
        kq_resp = send_receive_framed(sock, header_bytes, kq_req)
        assert kq_resp.startswith(b"KR00")

        arqc = kq_resp[4:].decode("ascii")
        assert len(arqc) == 16
        assert all(c in string.hexdigits for c in arqc)
        print("[PASS] Test Case 10 (KQ EMV ARQC) passed.")
    finally:
        if close_at_end:
            sock.close()


def test_tcp_framing_e2e():
    """
    Test Case 11: TCP 2-Byte Big-Endian Framing.
    Verify 2-byte big-endian prefix accurately encodes total response length.
    """
    print("\n--- Test Case 11: TCP Framing Verification ---")
    sock = get_client_socket()
    try:
        req_payload = b"NC"
        framed_request = struct.pack("!H", len(req_payload)) + req_payload
        sock.sendall(framed_request)

        len_prefix = recv_exact(sock, 2)
        resp_len = struct.unpack("!H", len_prefix)[0]
        resp_data = recv_exact(sock, resp_len)

        assert len(resp_data) == resp_len
        assert resp_data.startswith(b"ND00")
        print("[PASS] Test Case 11 (TCP Framing) passed.")
    finally:
        sock.close()


def test_header_mirroring_e2e():
    """
    Test Case 12: Header Mirroring Verification.
    Verify header bytes in request are mirrored verbatim in response frame.
    """
    print("\n--- Test Case 12: Header Mirroring Verification ---")
    header = b"H1"
    port = 1599
    hsm = PyThalesHSM(header=header, port=port)
    hsm.start_server(host="127.0.0.1", port=port, header_length=2, background=True)
    time.sleep(0.1)
    try:
        sock = get_client_socket(port=port)
        try:
            req_payload = b"NC"
            msg_body = header + req_payload
            framed_request = struct.pack("!H", len(msg_body)) + msg_body
            sock.sendall(framed_request)

            len_prefix = recv_exact(sock, 2)
            resp_len = struct.unpack("!H", len_prefix)[0]
            resp_data = recv_exact(sock, resp_len)

            assert resp_data.startswith(header)
            assert resp_data[2:4] == b"ND"
            assert resp_data[4:6] == b"00"
            print("[PASS] Test Case 12 (Header Mirroring) passed.")
        finally:
            sock.close()
    finally:
        hsm.stop_server()


def test_error_truncation_e2e():
    """
    Test Case 13: Error Response Truncation Rule.
    Verify that when Error Code != '00', payload following Error Code is empty.
    """
    print("\n--- Test Case 13: Error Response Truncation Verification ---")
    sock = get_client_socket()
    try:
        req_payload = b"XX"
        msg_len = len(req_payload)
        framed_request = struct.pack("!H", msg_len) + req_payload
        sock.sendall(framed_request)

        len_prefix = recv_exact(sock, 2)
        resp_len = struct.unpack("!H", len_prefix)[0]
        resp_data = recv_exact(sock, resp_len)

        err_code = resp_data[2:4].decode("ascii", errors="ignore")
        payload_after_err = resp_data[4:]

        assert err_code != "00"
        assert len(payload_after_err) == 0
        print("[PASS] Test Case 13 (Error Truncation) passed.")
    finally:
        sock.close()


def main():
    env_host = os.environ.get("HSM_HOST", "127.0.0.1")
    env_port_str = os.environ.get("HSM_PORT", "1500")
    env_header = os.environ.get("HSM_HEADER", "")

    try:
        default_port = int(env_port_str)
    except ValueError:
        default_port = 1500

    parser = argparse.ArgumentParser(
        description="HSM TCP Socket Test Client for pythales server verification"
    )
    parser.add_argument(
        "--host",
        default=env_host,
        help=f"HSM server host (default: {env_host})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"HSM server port (default: {default_port})",
    )
    parser.add_argument(
        "--header",
        default=env_header,
        help=f"Message header prefix (default: '{env_header}')",
    )

    args = parser.parse_args()

    header_bytes = args.header.encode("utf-8") if isinstance(args.header, str) else args.header

    print("==================================================")
    print(" pythales HSM Automated Test Verification Client ")
    print("==================================================")
    print(f" Target Host:    {args.host}")
    print(f" Target Port:    {args.port}")
    print(f" Message Header: {args.header!r}")

    local_server = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((args.host, args.port))
        sock.close()
    except Exception:
        print("Starting in-process HSM server for CLI test run...")
        local_server = PyThalesHSM(port=args.port)
        local_server.start_server(host=args.host, port=args.port, background=True)
        time.sleep(0.2)

    try:
        test_nc_diagnostics(header_bytes=header_bytes)
        test_a0_generate_key(header_bytes=header_bytes)
        test_bu_key_check_value(header_bytes=header_bytes)
        test_no_echo(header_bytes=header_bytes)
        test_n0_generate_random(header_bytes=header_bytes)
        test_ca_translate_pin(header_bytes=header_bytes)
        test_dc_verify_pin(header_bytes=header_bytes)
        test_cvv_workflow(header_bytes=header_bytes)
        test_m0_m2_data_encrypt(header_bytes=header_bytes)
        test_m6_generate_mac(header_bytes=header_bytes)
        test_kq_emv_arqc(header_bytes=header_bytes)
        test_tcp_framing_e2e()
        test_header_mirroring_e2e()
        test_error_truncation_e2e()
        tc_passed = True
    except Exception as e:
        print(f"\n[FAIL] Test execution error: {e}")
        tc_passed = False
    finally:
        if local_server:
            local_server.stop_server()

    print("\n==================================================")
    if tc_passed:
        print(" ALL VERIFICATION TESTS PASSED SUCCESSFULLY! [EXIT 0]")
        print("==================================================")
        return 0
    else:
        print(" VERIFICATION FAILED - ONE OR MORE TESTS FAILED! [EXIT 1]")
        print("==================================================")
        return 1


if __name__ == "__main__":
    sys.exit(main())
