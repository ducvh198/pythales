"""
Tests for PyThales Connection Management: Idle Timeout, Max Connections Throttling, and Keep-Alive.
"""

import socket
import struct
import time
import pytest
from pythales.hsm import PyThalesHSM


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def send_framed(sock, payload):
    framed = struct.pack("!H", len(payload)) + payload
    sock.sendall(framed)


def test_idle_timeout():
    """
    Verify that an idle connection with no data sent is closed by the server
    after idle_timeout expires.
    """
    port = 1610
    hsm = PyThalesHSM(port=port)
    hsm.start_server(port=port, idle_timeout=0.3, background=True)
    time.sleep(0.1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", port))

        # Do not send anything; wait longer than idle_timeout (0.3s)
        time.sleep(0.5)

        # Server should have closed the connection
        data = sock.recv(1024)
        assert data == b"", "Expected server to close connection due to idle timeout"
        sock.close()

    finally:
        hsm.stop_server()


def test_max_connections_limit():
    """
    Verify that max_connections limits active connections and rejects extra connections.
    """
    port = 1611
    max_conn = 2
    hsm = PyThalesHSM(port=port)
    hsm.start_server(port=port, max_connections=max_conn, background=True)
    time.sleep(0.1)

    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.connect(("127.0.0.1", port))
        send_framed(sock1, b"NC")
        time.sleep(0.05)

        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(("127.0.0.1", port))
        send_framed(sock2, b"NC")
        time.sleep(0.05)

        # 3rd connection attempt should be rejected / closed by server
        sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock3.settimeout(1.0)
        sock3.connect(("127.0.0.1", port))
        time.sleep(0.1)

        # Try reading or sending on sock3 -> server should have closed it
        data = sock3.recv(1024)
        assert data == b"", "Expected 3rd connection to be rejected when max_connections=2"
        sock3.close()

        # Close sock1 to free up a slot
        sock1.close()
        time.sleep(0.1)

        # 4th connection should now succeed
        sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock4.settimeout(2.0)
        sock4.connect(("127.0.0.1", port))
        send_framed(sock4, b"NC")
        len_buf = recv_exact(sock4, 2)
        assert len(len_buf) == 2
        payload_len = struct.unpack("!H", len_buf)[0]
        resp = recv_exact(sock4, payload_len)
        assert resp.startswith(b"ND00")

        sock2.close()
        sock4.close()

    finally:
        hsm.stop_server()


def test_tcp_keepalive():
    """
    Verify basic connectivity with enable_keepalive=True.
    """
    port = 1612
    hsm = PyThalesHSM(port=port)
    hsm.start_server(port=port, enable_keepalive=True, background=True)
    time.sleep(0.1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", port))

        send_framed(sock, b"NC")
        len_buf = recv_exact(sock, 2)
        payload_len = struct.unpack("!H", len_buf)[0]
        resp = recv_exact(sock, payload_len)
        assert resp.startswith(b"ND00")

        sock.close()
    finally:
        hsm.stop_server()
