"""
Empirical Concurrency & Socket Stress Testing Suite for Milestone M5.
Target: AsyncHSMServer & PyThalesHSM facade across PayShield 10K host commands.
Author: Challenger 2 (challenger_m5_2)
"""

import socket
import struct
import threading
import queue
import time
import pytest
from pythales.hsm import PyThalesHSM


def get_free_port() -> int:
    """Helper to obtain an OS-assigned available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


STRESS_PORT = get_free_port()


@pytest.fixture(scope="module", autouse=True)
def live_stress_server():
    """Start an AsyncHSMServer instance on an available TCP port for concurrency testing."""
    hsm = PyThalesHSM(port=STRESS_PORT)
    hsm.start_server(host="127.0.0.1", port=STRESS_PORT, background=True)
    time.sleep(0.2)
    yield hsm
    hsm.stop_server()
    time.sleep(0.1)


def send_receive_framed(sock, header_bytes, command_payload_bytes):
    """Send a framed command and receive framed response over raw socket."""
    msg_body = header_bytes + command_payload_bytes
    framed_request = struct.pack("!H", len(msg_body)) + msg_body
    sock.sendall(framed_request)

    len_bytes = b""
    while len(len_bytes) < 2:
        chunk = sock.recv(2 - len(len_bytes))
        if not chunk:
            raise ConnectionError("Socket closed prematurely reading length header")
        len_bytes += chunk

    resp_len = struct.unpack("!H", len_bytes)[0]
    resp_data = b""
    while len(resp_data) < resp_len:
        chunk = sock.recv(resp_len - len(resp_data))
        if not chunk:
            raise ConnectionError("Socket closed prematurely reading payload")
        resp_data += chunk

    if header_bytes:
        if not resp_data.startswith(header_bytes):
            raise ValueError(f"Header mismatch: expected {header_bytes!r}, got {resp_data[:len(header_bytes)]!r}")
        return resp_data[len(header_bytes):]
    return resp_data


def test_concurrent_all_9_payshield_commands():
    """
    Testing Requirement 1:
    Multi-threaded socket client test harness executing concurrent TCP requests
    against AsyncHSMServer across 9 PayShield commands:
    NC, A0, BU, CA, DC, CW, M0, M6, KQ.
    """
    num_threads = 27  # 3 worker threads per command
    iterations_per_thread = 15
    results_queue = queue.Queue()

    def worker(cmd_type, worker_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", STRESS_PORT))

            # Helper keys for CA, DC, CW, M0, M6, KQ
            gen_key_resp = send_receive_framed(sock, b"", b"A00000U")
            k1 = gen_key_resp[4:37].decode("ascii")

            for _ in range(iterations_per_thread):
                if cmd_type == "NC":
                    resp = send_receive_framed(sock, b"", b"NC")
                    assert resp.startswith(b"ND00"), f"NC failed: {resp}"

                elif cmd_type == "A0":
                    resp = send_receive_framed(sock, b"", b"A00000U")
                    assert resp.startswith(b"A100"), f"A0 failed: {resp}"
                    assert len(resp) == 4 + 39

                elif cmd_type == "BU":
                    req = f"BU000{k1}".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"BV00"), f"BU failed: {resp}"

                elif cmd_type == "CA":
                    req = f"CA{k1}{k1}122B687AEFC34B1A890101001123456789".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"CB"), f"CA failed: {resp}"

                elif cmd_type == "DC":
                    pvk = "1234567890ABCDEF1234567890ABCDEF"
                    req = f"DC{k1}{pvk}2B687AEFC34B1A890100112345678911234".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"DD"), f"DC failed: {resp}"

                elif cmd_type == "CW":
                    req = f"CW{k1}4111111111111111;2512101".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"CX00"), f"CW failed: {resp}"

                elif cmd_type == "M0":
                    plaintext_hex = "504159534849454C44313233343536"
                    req = f"M0{k1}0000F{plaintext_hex}".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"M100"), f"M0 failed: {resp}"

                elif cmd_type == "M6":
                    plaintext_hex = "504159534849454C4431323334353637"
                    req = f"M6{k1}000010{plaintext_hex}".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"M700"), f"M6 failed: {resp}"

                elif cmd_type == "KQ":
                    req = f"KQ1{k1}4111111111111111;0100010010504159534849454C44313233343536".encode("ascii")
                    resp = send_receive_framed(sock, b"", req)
                    assert resp.startswith(b"KR00"), f"KQ failed: {resp}"

            sock.close()
            results_queue.put((True, cmd_type, None))
        except Exception as e:
            results_queue.put((False, cmd_type, str(e)))

    commands = ["NC", "A0", "BU", "CA", "DC", "CW", "M0", "M6", "KQ"]
    threads = []
    for i in range(num_threads):
        cmd = commands[i % len(commands)]
        t = threading.Thread(target=worker, args=(cmd, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    failures = []
    while not results_queue.empty():
        success, cmd, err = results_queue.get()
        if not success:
            failures.append(f"{cmd}: {err}")

    assert len(failures) == 0, f"Concurrent 9 PayShield commands test failed with errors: {failures}"


def test_high_concurrency_stress():
    """
    Testing Requirement 2 - Part 1: High concurrency.
    50 concurrent threads making 20 requests each (1000 total TCP requests).
    """
    num_threads = 50
    requests_per_thread = 20
    results_queue = queue.Queue()

    def worker(worker_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", STRESS_PORT))

            for j in range(requests_per_thread):
                echo_str = f"THREAD_{worker_id}_REQ_{j}"
                req = f"NO{echo_str}".encode("ascii")
                resp = send_receive_framed(sock, b"", req)
                assert resp.startswith(b"NP00")
                assert resp[4:].decode("ascii") == echo_str

            sock.close()
            results_queue.put((True, None))
        except Exception as e:
            results_queue.put((False, str(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    start_time = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.time() - start_time

    failures = []
    while not results_queue.empty():
        success, err = results_queue.get()
        if not success:
            failures.append(err)

    assert len(failures) == 0, f"High concurrency stress test failed: {failures}"
    print(f"\n[STRESS] Executed 1000 concurrent requests across 50 threads in {duration:.2f}s")


def test_rapid_connect_disconnect_thrashing():
    """
    Testing Requirement 2 - Part 2: Rapid connect/disconnect connection thrashing.
    30 threads rapidly opening connections, sending 1 command, closing immediately.
    Total connections created & torn down: 30 * 20 = 600 connections.
    """
    num_threads = 30
    cycles_per_thread = 20
    results_queue = queue.Queue()

    def worker(worker_id):
        try:
            for j in range(cycles_per_thread):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect(("127.0.0.1", STRESS_PORT))

                resp = send_receive_framed(sock, b"", b"NC")
                assert resp.startswith(b"ND00")

                sock.close()
            results_queue.put((True, None))
        except Exception as e:
            results_queue.put((False, str(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    failures = []
    while not results_queue.empty():
        success, err = results_queue.get()
        if not success:
            failures.append(err)

    assert len(failures) == 0, f"Rapid connect/disconnect thrashing failed: {failures}"


def test_connection_pooling():
    """
    Testing Requirement 2 - Part 3: Connection pooling.
    Maintains a pool of pre-established TCP sockets and borrows/returns them
    concurrently across worker threads.
    """
    pool_size = 10
    num_workers = 20
    ops_per_worker = 15

    class ThreadSafeSocketPool:
        def __init__(self, host, port, size):
            self.host = host
            self.port = port
            self.size = size
            self.pool = queue.Queue(maxsize=size)
            for _ in range(size):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.host, self.port))
                self.pool.put(sock)

        def acquire(self):
            return self.pool.get(timeout=5.0)

        def release(self, sock):
            self.pool.put(sock)

        def close_all(self):
            while not self.pool.empty():
                try:
                    sock = self.pool.get_nowait()
                    sock.close()
                except queue.Empty:
                    break

    pool = ThreadSafeSocketPool("127.0.0.1", STRESS_PORT, pool_size)
    results_queue = queue.Queue()

    def worker(worker_id):
        try:
            for _ in range(ops_per_worker):
                sock = pool.acquire()
                try:
                    resp = send_receive_framed(sock, b"", b"NC")
                    assert resp.startswith(b"ND00")
                finally:
                    pool.release(sock)
            results_queue.put((True, None))
        except Exception as e:
            results_queue.put((False, str(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    pool.close_all()

    failures = []
    while not results_queue.empty():
        success, err = results_queue.get()
        if not success:
            failures.append(err)

    assert len(failures) == 0, f"Connection pooling stress test failed: {failures}"


def test_pipelined_socket_requests():
    """
    Adversarial Stress Test: Request Pipelining.
    Sends 30 requests back-to-back on a single socket without waiting for
    individual responses, then reads and verifies all 30 framed responses.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect(("127.0.0.1", STRESS_PORT))

    count = 30
    request_stream = b""
    expected_echoes = []
    for i in range(count):
        echo_data = f"PIPE_DATA_{i}".encode("ascii")
        expected_echoes.append(echo_data)
        req_body = b"NO" + echo_data
        request_stream += struct.pack("!H", len(req_body)) + req_body

    sock.sendall(request_stream)

    for i in range(count):
        len_bytes = b""
        while len(len_bytes) < 2:
            chunk = sock.recv(2 - len(len_bytes))
            if not chunk:
                raise ConnectionError("Socket closed during pipelined read")
            len_bytes += chunk
        resp_len = struct.unpack("!H", len_bytes)[0]

        resp_body = b""
        while len(resp_body) < resp_len:
            chunk = sock.recv(resp_len - len(resp_body))
            if not chunk:
                raise ConnectionError("Socket closed during pipelined payload read")
            resp_body += chunk

        assert resp_body.startswith(b"NP00")
        assert resp_body[4:] == expected_echoes[i]

    sock.close()


def test_abrupt_disconnect_resilience():
    """
    Adversarial Stress Test: Abrupt disconnect and malformed framing handling.
    Verifies that client disconnects or malformed length claims do not crash the server.
    """
    # 1. Send incomplete length prefix then disconnect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", STRESS_PORT))
    sock.sendall(b"\x00")  # Only 1 byte sent
    sock.close()

    # 2. Send length prefix claim of 1000 bytes, but send only 10 bytes then close
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", STRESS_PORT))
    sock.sendall(struct.pack("!H", 1000) + b"INCOMPLETE")
    sock.close()

    time.sleep(0.15)

    # 3. Verify server is still completely responsive to valid clients
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    sock.connect(("127.0.0.1", STRESS_PORT))
    resp = send_receive_framed(sock, b"", b"NC")
    assert resp.startswith(b"ND00")
    sock.close()


def test_header_mirroring_concurrency():
    """
    Adversarial Stress Test: Header Mirroring under Concurrent Multi-Threaded Load.
    Runs server on a dynamic port with header 'HDR1' (4 bytes).
    20 threads execute concurrent requests to ensure header prefix is accurately mirrored.
    """
    header = b"HDR1"
    port = get_free_port()
    hsm = PyThalesHSM(header=header, port=port)
    hsm.start_server(host="127.0.0.1", port=port, header_length=4, background=True)
    time.sleep(0.2)

    num_threads = 20
    results_queue = queue.Queue()

    def worker(worker_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", port))

            for j in range(10):
                resp = send_receive_framed(sock, header, b"NC")
                assert resp.startswith(b"ND00")

            sock.close()
            results_queue.put((True, None))
        except Exception as e:
            results_queue.put((False, str(e)))

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        failures = []
        while not results_queue.empty():
            success, err = results_queue.get()
            if not success:
                failures.append(err)

        assert len(failures) == 0, f"Header mirroring concurrency failed: {failures}"
    finally:
        hsm.stop_server()
        time.sleep(0.1)
