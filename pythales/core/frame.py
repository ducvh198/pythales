"""
Message framing parser and response formatter for PayShield TCP/IP communication.
"""

import struct
from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class CommandFrame:
    header_bytes: bytes
    command_code: str
    payload_bytes: bytes
    raw_body: bytes
    delimiter_present: bool = False
    trailer_bytes: bytes = b""


@dataclass
class ResponseFrame:
    header_bytes: bytes
    response_code: str
    error_code: str
    payload_bytes: bytes = b""

    def build(self, include_length_prefix: bool = False) -> bytes:
        return MessageFraming.format_response(
            header_bytes=self.header_bytes,
            response_code=self.response_code,
            error_code=self.error_code,
            payload_bytes=self.payload_bytes,
            include_length_prefix=include_length_prefix
        )


class MessageFraming:
    @staticmethod
    def parse_request(raw_data: bytes, header_length: int = 0) -> CommandFrame:
        """
        Parse raw request bytes according to TCP envelope specification:
        [2-Byte TCP Length] + [Message Header (m A)] + [Command Code (2 A)] + [Data Fields] + [Delimiter (0x19)] (Optional) + [Message Trailer]
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

        delimiter_present = False
        trailer_bytes = b""

        if len(body) < 2:
            command_code = body.decode("ascii", errors="ignore").upper() if body else ""
            payload_bytes = b""
        else:
            command_code = body[:2].decode("ascii", errors="ignore").upper()
            rem = body[2:]
            delim_pos = rem.find(b"\x19")
            if delim_pos != -1:
                payload_bytes = rem[:delim_pos]
                delimiter_present = True
                trailer_bytes = rem[delim_pos + 1:]
            else:
                payload_bytes = rem

        return CommandFrame(
            header_bytes=header_bytes,
            command_code=command_code,
            payload_bytes=payload_bytes,
            raw_body=body,
            delimiter_present=delimiter_present,
            trailer_bytes=trailer_bytes
        )

    @staticmethod
    def format_response(
        header_bytes: bytes,
        response_code: Union[str, bytes],
        error_code: Union[str, bytes],
        payload_bytes: Union[str, bytes] = b"",
        include_length_prefix: bool = False
    ) -> bytes:
        """
        Format response payload according to PayShield response envelope specification:
        [2-Byte TCP Length] (Optional) + [Echoed Header] + [Response Code (2 A)] + [Error Code (2 A/N)] + [Response Data]

        TRUNCATION RULE: When Error Code != '00', HSM MUST discard all Response Data fields and end immediately after Error Code.
        """
        resp_str = response_code.decode("ascii", errors="ignore") if isinstance(response_code, bytes) else str(response_code)
        err_str = error_code.decode("ascii", errors="ignore") if isinstance(error_code, bytes) else str(error_code)

        # TRUNCATION RULE: When Error Code != '00', discard all response data
        if err_str != "00":
            effective_payload = b""
        else:
            if isinstance(payload_bytes, str):
                effective_payload = payload_bytes.encode("ascii")
            else:
                effective_payload = payload_bytes or b""

        body = resp_str.encode("ascii") + err_str.encode("ascii") + effective_payload
        response_msg = header_bytes + body

        if include_length_prefix:
            length_prefix = struct.pack("!H", len(response_msg))
            return length_prefix + response_msg

        return response_msg

