"""Regression tests for synchronous background-server lifecycle reporting."""

import socket

import pytest

from pythales.hsm import PyThalesHSM


def test_background_start_propagates_bind_error():
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind(("127.0.0.1", 0))
    occupied.listen(1)
    port = occupied.getsockname()[1]
    hsm = PyThalesHSM(port=port)

    try:
        with pytest.raises(OSError):
            hsm.start_server(host="127.0.0.1", background=True)
        assert not hsm.is_server_running()
    finally:
        hsm.stop_server()
        occupied.close()


def test_stop_server_joins_thread_and_closes_loop():
    hsm = PyThalesHSM(port=0)
    hsm.start_server(host="127.0.0.1", background=True)
    thread = hsm._server_thread
    loop = hsm._server_loop

    assert hsm.is_server_running()
    hsm.stop_server()

    assert not thread.is_alive()
    assert loop.is_closed()
    assert not hsm.is_server_running()
