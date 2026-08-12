"""
Async TCP Server implementation for PyThales PayShield 10K Simulator.
"""

import asyncio
import struct
import logging
from typing import Optional, Union, Any

from pythales.core.frame import MessageFraming, CommandFrame, ResponseFrame
from pythales.core.router import global_router, Router
from pythales.core.errors import ErrorCodes, PayShieldException

logger = logging.getLogger("pythales.server")


class AsyncHSMServer:
    """
    Async TCP Server for PayShield Host Command Processing.

    Handles client connections using asyncio TCP streams:
    1. Parses 2-byte big-endian length header prefix.
    2. Unpacks Header (if present) and 2-character Command Code.
    3. Dispatches request payload to PyThales Router.
    4. Applies PayShield Error Code Truncation Rule: if response error code != '00',
       all response payload data following the 2-byte error code is truncated.
    5. Packages response with mirrored Header, 2-character Response Code, Error Code,
       prepending 2-byte big-endian response length prefix.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1500,
        header: bytes = b"",
        header_length: Optional[int] = None,
        hsm: Optional[Any] = None,
        max_connections: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        enable_keepalive: bool = True,
    ):
        self.host = host
        self.port = port
        self.header = header
        self.header_length = header_length
        self._hsm = hsm
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.enable_keepalive = enable_keepalive
        self._server: Optional[asyncio.AbstractServer] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_connections: int = 0

    @property
    def active_connections(self) -> int:
        return self._active_connections

    @property
    def hsm(self) -> Any:
        if self._hsm is None:
            from pythales.hsm import HSM
            self._hsm = HSM(header=self.header, port=self.port)
        return self._hsm

    @hsm.setter
    def hsm(self, value: Any):
        self._hsm = value

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    async def start(self) -> None:
        """Start the async TCP server on the configured host and port."""
        if self.is_running:
            return
        if self.max_connections is not None and self.max_connections > 0:
            self._semaphore = asyncio.Semaphore(self.max_connections)
        else:
            self._semaphore = None

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
        )
        logger.info(f"AsyncHSMServer listening on {self.host}:{self.port}")

    async def serve_forever(self) -> None:
        """Serve requests indefinitely until cancelled or stopped."""
        if not self.is_running:
            await self.start()
        if self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Stop the async TCP server and close active sockets."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self._semaphore = None
            logger.info("AsyncHSMServer stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle an incoming client TCP socket stream connection.
        """
        client_peer = writer.get_extra_info("peername")
        logger.debug(f"Client connected: {client_peer}")

        client_socket = writer.get_extra_info("socket")
        if self.enable_keepalive and client_socket is not None:
            try:
                import socket
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception as e:
                logger.debug(f"Could not set SO_KEEPALIVE on client socket: {e}")

        if self._semaphore is not None:
            if self._semaphore.locked():
                logger.warning(
                    f"Max connections ({self.max_connections}) reached. Rejecting client {client_peer}"
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            await self._semaphore.acquire()

        self._active_connections += 1

        hdr_len = (
            self.header_length
            if self.header_length is not None
            else (len(self.header) if self.header else 0)
        )

        try:
            while True:
                try:
                    if self.idle_timeout is not None and self.idle_timeout > 0:
                        len_bytes = await asyncio.wait_for(
                            reader.readexactly(2), timeout=self.idle_timeout
                        )
                    else:
                        len_bytes = await reader.readexactly(2)
                except asyncio.TimeoutError:
                    logger.warning(
                        f"Client {client_peer} idle timeout ({self.idle_timeout}s) expired."
                    )
                    break
                except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
                    break

                if not len_bytes:
                    break

                frame_len = struct.unpack("!H", len_bytes)[0]
                try:
                    if self.idle_timeout is not None and self.idle_timeout > 0:
                        raw_payload = await asyncio.wait_for(
                            reader.readexactly(frame_len), timeout=self.idle_timeout
                        )
                    else:
                        raw_payload = await reader.readexactly(frame_len)
                except asyncio.TimeoutError:
                    logger.warning(
                        f"Client {client_peer} frame payload read timeout ({self.idle_timeout}s) expired."
                    )
                    break
                except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
                    break

                # Process message using HSM instance process_raw_message
                resp_body = self.hsm.process_raw_message(
                    raw_payload, header_length=hdr_len
                )

                # Prepend 2-byte big-endian TCP length prefix to response body
                resp_framed = struct.pack("!H", len(resp_body)) + resp_body

                writer.write(resp_framed)
                await writer.drain()

        except Exception as e:
            logger.error(f"Error handling client {client_peer}: {e}")
        finally:
            self._active_connections = max(0, self._active_connections - 1)
            if self._semaphore is not None:
                self._semaphore.release()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Client disconnected: {client_peer}")


AsyncTCPServer = AsyncHSMServer
AsyncServer = AsyncHSMServer

