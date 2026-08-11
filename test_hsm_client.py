#!/usr/bin/env python3
"""
HSM Socket Client Test Verification Script for pythales.

Connects to a pythales HSM server via TCP socket, sends diagnostic (NC)
and key generation (A0) commands, and verifies the response header echo,
response code, error code, and payload contents.
"""

import argparse
import os
import socket
import struct
import sys
import string


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
    
    # Validate header echo if header is non-empty
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


def test_nc_diagnostics(sock, header_bytes):
    """
    Test Case 1: Send NC (Diagnostics) command.
    Verify:
    - Response Code is 'ND'
    - Error Code is '00'
    - Payload contains 16-char LMK check value and Firmware Version (e.g. '0007-E000')
    """
    print("\n--- Test Case 1: Send NC (Diagnostics) Command ---")
    req_payload = b"NC"
    print(f"Sending framed request: NC (Header: {header_bytes!r})")
    
    try:
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
    except Exception as e:
        print(f"[FAIL] Error communicating with server: {e}")
        return False

    if len(resp_payload) < 4:
        print(f"[FAIL] Response payload too short ({len(resp_payload)} bytes): {resp_payload!r}")
        return False

    resp_code = resp_payload[:2].decode("utf-8", errors="replace")
    err_code = resp_payload[2:4].decode("utf-8", errors="replace")
    remaining = resp_payload[4:]

    print(f"  Response Code: '{resp_code}'")
    print(f"  Error Code:    '{err_code}'")

    if resp_code != "ND":
        print(f"[FAIL] Invalid response code: expected 'ND', got '{resp_code}'")
        return False

    if err_code != "00":
        print(f"[FAIL] Non-zero error code: expected '00', got '{err_code}'")
        return False

    if len(remaining) < 16:
        print(f"[FAIL] Response payload too short for LMK Check Value: {len(remaining)} bytes remaining")
        return False

    lmk_cv = remaining[:16].decode("utf-8", errors="replace")
    firmware_ver = remaining[16:].decode("utf-8", errors="replace")

    print(f"  LMK Check Value: '{lmk_cv}'")
    print(f"  Firmware Version: '{firmware_ver}'")

    if not all(c in string.hexdigits for c in lmk_cv):
        print(f"[FAIL] LMK Check Value is not valid hex: '{lmk_cv}'")
        return False

    if not firmware_ver:
        print("[FAIL] Firmware version is empty")
        return False

    print("[PASS] Test Case 1 (NC Diagnostics) passed successfully.")
    return True


def test_a0_generate_key(sock, header_bytes):
    """
    Test Case 2: Send A0 (Generate Key) command.
    Verify:
    - Response Code is 'A1'
    - Error Code is '00'
    - Response key payload scheme is 'U' + 32-char hex key
    """
    print("\n--- Test Case 2: Send A0 (Generate Key) Command ---")
    # A0 Request: Mode='0' (1 byte), Key Type='000' (3 bytes), Key Scheme='U' (1 byte)
    req_payload = b"A00000U"
    print(f"Sending framed request: A00000U (Header: {header_bytes!r})")

    try:
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
    except Exception as e:
        print(f"[FAIL] Error communicating with server: {e}")
        return False

    if len(resp_payload) < 4:
        print(f"[FAIL] Response payload too short ({len(resp_payload)} bytes): {resp_payload!r}")
        return False

    resp_code = resp_payload[:2].decode("utf-8", errors="replace")
    err_code = resp_payload[2:4].decode("utf-8", errors="replace")
    key_payload = resp_payload[4:].decode("utf-8", errors="replace")

    print(f"  Response Code: '{resp_code}'")
    print(f"  Error Code:    '{err_code}'")
    print(f"  Key Payload:   '{key_payload}'")

    if resp_code != "A1":
        print(f"[FAIL] Invalid response code: expected 'A1', got '{resp_code}'")
        return False

    if err_code != "00":
        print(f"[FAIL] Non-zero error code: expected '00', got '{err_code}'")
        return False

    if len(key_payload) != 33:
        print(f"[FAIL] Expected 33-char key payload (U + 32 hex chars), got {len(key_payload)} chars")
        return False

    if not key_payload.startswith("U"):
        print(f"[FAIL] Expected key scheme 'U', got '{key_payload[0]}'")
        return False

    hex_key = key_payload[1:]
    if not all(c in string.hexdigits for c in hex_key):
        print(f"[FAIL] Key string contains non-hex characters: '{hex_key}'")
        return False

    print("[PASS] Test Case 2 (A0 Generate Key) passed successfully.")
    return True


def test_no_echo(sock, header_bytes):
    """
    Test Case 3: Send NO (Network Echo Test) command.
    Verify NP response and identical echoed payload.
    """
    print("\n--- Test Case 3: Send NO (Network Echo Test) Command ---")
    req_payload = b"NOPAYSHIELD_ECHO_DATA_1234"
    try:
        resp_payload = send_receive_framed(sock, header_bytes, req_payload)
    except Exception as e:
        print(f"[FAIL] Error communicating with server: {e}")
        return False

    resp_code = resp_payload[:2].decode("utf-8", errors="replace")
    err_code = resp_payload[2:4].decode("utf-8", errors="replace")
    echo_data = resp_payload[4:]

    print(f"  Response Code: '{resp_code}'")
    print(f"  Error Code:    '{err_code}'")
    print(f"  Echo Data:     {echo_data!r}")

    if resp_code != "NP" or err_code != "00" or echo_data != b"PAYSHIELD_ECHO_DATA_1234":
        print(f"[FAIL] NO Echo failed: expected NP 00 PAYSHIELD_ECHO_DATA_1234")
        return False

    print("[PASS] Test Case 3 (NO Network Echo) passed successfully.")
    return True


def test_cvv_workflow(sock, header_bytes):
    """
    Test Case 4: CW (Generate CVV) and CY (Verify CVV).
    """
    print("\n--- Test Case 4: Send CW (Generate CVV) & CY (Verify CVV) ---")
    # Generate CVK key (KeyType 003)
    gen_cw = send_receive_framed(sock, header_bytes, b"A00003U")
    cvk_key = gen_cw[4:4+33].decode("ascii")

    # CW Generate CVV
    cw_req = f"CW{cvk_key}41111111111111112512101".encode("ascii")
    cw_resp = send_receive_framed(sock, header_bytes, cw_req)
    if not cw_resp.startswith(b"CX00"):
        print(f"[FAIL] CW response error: {cw_resp!r}")
        return False

    cvv = cw_resp[4:].decode("ascii")
    print(f"  Generated CVV: '{cvv}'")

    # CY Verify CVV
    cy_req = f"CY{cvk_key}{cvv}4111111111111111112512101".encode("ascii")
    cy_resp = send_receive_framed(sock, header_bytes, cy_req)
    if cy_resp != b"CZ00":
        print(f"[FAIL] CY verify failed: {cy_resp!r}")
        return False

    print("[PASS] Test Case 4 (CW/CY CVV Workflow) passed successfully.")
    return True


def test_m0_m2_data_encrypt(sock, header_bytes):
    """
    Test Case 5: M0 (Encrypt Data) and M2 (Decrypt Data).
    """
    print("\n--- Test Case 5: Send M0 (Encrypt Data) & M2 (Decrypt Data) ---")
    # Generate DEK key (KeyType 008)
    gen_dek = send_receive_framed(sock, header_bytes, b"A00008U")
    dek_key = gen_dek[4:4+33].decode("ascii")

    # M0 Encrypt
    plaintext_hex = "504159534849454C44313233343536"
    m0_req = f"M0{dek_key}0000F{plaintext_hex}".encode("ascii")
    m0_resp = send_receive_framed(sock, header_bytes, m0_req)
    if not m0_resp.startswith(b"M100"):
        print(f"[FAIL] M0 encrypt failed: {m0_resp!r}")
        return False

    enc_hex = m0_resp[4:].decode("ascii")
    print(f"  Encrypted Hex: '{enc_hex}'")

    # M2 Decrypt
    len_hex = f"{len(enc_hex) // 2:04X}"
    m2_req = f"M2{dek_key}0{len_hex}{enc_hex}".encode("ascii")
    m2_resp = send_receive_framed(sock, header_bytes, m2_req)
    if not m2_resp.startswith(b"M300"):
        print(f"[FAIL] M2 decrypt failed: {m2_resp!r}")
        return False

    dec_hex = m2_resp[4:].decode("ascii")
    print(f"  Decrypted Hex: '{dec_hex}'")

    if dec_hex != plaintext_hex:
        print(f"[FAIL] Decrypted text mismatch: expected {plaintext_hex}, got {dec_hex}")
        return False

    print("[PASS] Test Case 5 (M0/M2 Data Encryption) passed successfully.")
    return True


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
        help=f"HSM server host (default: {env_host})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"HSM server port (default: {default_port})"
    )
    parser.add_argument(
        "--header",
        default=env_header,
        help=f"Message header prefix (default: '{env_header}')"
    )

    args = parser.parse_args()

    header_bytes = args.header.encode("utf-8") if isinstance(args.header, str) else args.header

    print("==================================================")
    print(" pythales HSM Automated Test Verification Client ")
    print("==================================================")
    print(f" Target Host:   {args.host}")
    print(f" Target Port:   {args.port}")
    print(f" Message Header: {args.header!r}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((args.host, args.port))
        print(f" Successfully connected to HSM server at {args.host}:{args.port}")
    except Exception as e:
        print(f"\n[FAIL] Failed to connect to HSM server at {args.host}:{args.port}: {e}")
        return 1

    try:
        tc1_passed = test_nc_diagnostics(sock, header_bytes)
        tc2_passed = test_a0_generate_key(sock, header_bytes)
        tc3_passed = test_no_echo(sock, header_bytes)
        tc4_passed = test_cvv_workflow(sock, header_bytes)
        tc5_passed = test_m0_m2_data_encrypt(sock, header_bytes)
    finally:
        sock.close()

    print("\n==================================================")
    if all([tc1_passed, tc2_passed, tc3_passed, tc4_passed, tc5_passed]):
        print(" ALL VERIFICATION TESTS PASSED SUCCESSFULLY! [EXIT 0]")
        print("==================================================")
        return 0
    else:
        print(" VERIFICATION FAILED - ONE OR MORE TESTS FAILED! [EXIT 1]")
        print("==================================================")
        return 1



if __name__ == "__main__":
    sys.exit(main())
