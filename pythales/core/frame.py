"""
Message framing parser and response formatter for PayShield TCP/IP communication.
"""

import struct
from dataclasses import dataclass
from typing import Tuple, Optional


@dataclass
class CommandFrame:
    header_bytes: bytes
    command_code: str
    payload_bytes: bytes
    raw_body: bytes


class MessageFraming:
    @staticmethod
    def parse_request(raw_data: bytes, header_length: int = 0) -> CommandFrame:
        """
        Parse raw message bytes.
        If raw_data has length prefix (e.g. 2 bytes), strip or parse it if included.
        """
        data = raw_data
        if len(data) >= 2:
            expected_len = struct.unpack("!H", data[:2])[0]
            if len(data) == expected_len + 2:
                data = data[2:]

        if header_length > 0 and len(data) >= header_length:
            header_bytes = data[:header_length]
            body = data[header_length:]
        else:
            header_bytes = b""
            body = data

        if len(body) < 2:
            command_code = body.decode("ascii", errors="ignore").upper() if body else ""
            payload_bytes = b""
        else:
            command_code = body[:2].decode("ascii", errors="ignore").upper()
            payload_bytes = body[2:]

        return CommandFrame(
            header_bytes=header_bytes,
            command_code=command_code,
            payload_bytes=payload_bytes,
            raw_body=body
        )

    @staticmethod
    def format_response(header_bytes: bytes, response_code: str, error_code: str, payload_bytes: bytes = b"") -> bytes:
        """
        Format response payload:
        [Header (echoed)] + [Response Code (2 chars)] + [Error Code (2 chars)] + [Payload]
        """
        body = response_code.encode("ascii") + error_code.encode("ascii") + payload_bytes
        return header_bytes + body
