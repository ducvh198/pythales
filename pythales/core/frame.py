"""
Message framing parser and response formatter for PayShield TCP/IP communication.
"""

import string
import struct
from dataclasses import dataclass
from typing import Optional, Union

from pythales.core.errors import ErrorCodes, PayShieldException


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

        minimum_length = header_length + 2
        if len(data) < minimum_length:
            raise PayShieldException(
                ErrorCodes.INVALID_INPUT_DATA,
                f"Message is too short: expected at least {minimum_length} bytes, got {len(data)}",
            )

        if header_length > 0:
            header_bytes = data[:header_length]
            body = data[header_length:]
        else:
            header_bytes = b""
            body = data

        delimiter_present = False
        trailer_bytes = b""

        try:
            command_code = body[:2].decode("ascii").upper()
        except UnicodeDecodeError as exc:
            raise PayShieldException(ErrorCodes.INVALID_INPUT_DATA, "Command code is not ASCII") from exc

        rem = body[2:]
        delim_pos = -1
        if command_code == "LQ" and len(rem) >= 12:
            try:
                key_fmt = rem[6:8]
                key_len_field = rem[8:12]
                offset = 12
                if key_fmt == b"04":
                    if rem[offset:offset + 1] in (b"S", b"R"):
                        kb_len = 1 + int(rem[offset + 2:offset + 6].decode("ascii"))
                    else:
                        kb_len = int(rem[offset + 1:offset + 5].decode("ascii"))
                    offset += kb_len
                else:
                    key_len = int(key_len_field.decode("ascii"))
                    offset += key_len
                if offset < len(rem) and rem[offset:offset + 1] == b";":
                    offset += 1
                data_len = int(rem[offset:offset + 5].decode("ascii"))
                offset += 5 + data_len
                if len(rem) > offset and rem[offset:offset + 1] == b"\x19":
                    delim_pos = offset
                elif len(rem) == offset:
                    delim_pos = -1
                else:
                    delim_pos = rem.find(b"\x19", offset)
            except Exception:
                delim_pos = -1
        elif command_code == "LS" and len(rem) >= 12:
            try:
                hmac_len = int(rem[2:6].decode("ascii"))
                offset = 6 + hmac_len
                key_fmt = rem[offset:offset + 2]
                key_len_field = rem[offset + 2:offset + 6]
                offset += 6
                if key_fmt == b"04":
                    if rem[offset:offset + 1] in (b"S", b"R"):
                        kb_len = 1 + int(rem[offset + 2:offset + 6].decode("ascii"))
                    else:
                        kb_len = int(rem[offset + 1:offset + 5].decode("ascii"))
                    offset += kb_len
                else:
                    key_len = int(key_len_field.decode("ascii"))
                    offset += key_len
                if offset < len(rem) and rem[offset:offset + 1] == b";":
                    offset += 1
                data_len = int(rem[offset:offset + 5].decode("ascii"))
                offset += 5 + data_len
                if len(rem) > offset and rem[offset:offset + 1] == b"\x19":
                    delim_pos = offset
                elif len(rem) == offset:
                    delim_pos = -1
                else:
                    delim_pos = rem.find(b"\x19", offset)
            except Exception:
                delim_pos = -1
        elif command_code == "LU" and len(rem) >= 16:
            try:
                if rem.startswith((b"S", b"R")):
                    if rem.startswith(b"S") and len(rem) >= 5 and rem[1:5].isdigit():
                        zmk_len = int(rem[1:5].decode("ascii"))
                    elif len(rem) >= 6 and rem[2:6].isdigit():
                        zmk_len = 1 + int(rem[2:6].decode("ascii"))
                    else:
                        zmk_len = 16
                else:
                    scheme = chr(rem[0]).upper()
                    if scheme in ("U", "X", "M"):
                        zmk_len = 33
                    elif scheme in ("T", "Y"):
                        zmk_len = 49
                    elif scheme in ("D", "A"):
                        zmk_len = 33 if len(rem) >= 33 else 17
                    elif scheme == "E":
                        zmk_len = 49 if len(rem) >= 49 else (33 if len(rem) >= 33 else 17)
                    elif scheme == "Z":
                        zmk_len = 17
                    else:
                        zmk_len = 48 if len(rem) >= 48 and all(chr(c) in string.hexdigits for c in rem[:48]) else 32
                offset = zmk_len
                len_field = rem[offset:offset + 4]
                offset += 4
                if len_field == b"FFFF":
                    if rem[offset:offset + 1] in (b"S", b"R"):
                        kb_len = 1 + int(rem[offset + 2:offset + 6].decode("ascii"))
                    else:
                        kb_len = int(rem[offset + 1:offset + 5].decode("ascii"))
                    offset += kb_len
                else:
                    key_len = int(len_field.decode("ascii"))
                    offset += key_len
                delim_pos = rem.find(b"\x19", offset)
            except Exception:
                delim_pos = -1
        elif command_code == "LW" and len(rem) >= 16:
            try:
                if rem.startswith((b"S", b"R")):
                    if rem.startswith(b"S") and len(rem) >= 5 and rem[1:5].isdigit():
                        zmk_len = int(rem[1:5].decode("ascii"))
                    elif len(rem) >= 6 and rem[2:6].isdigit():
                        zmk_len = 1 + int(rem[2:6].decode("ascii"))
                    else:
                        zmk_len = 16
                else:
                    scheme = chr(rem[0]).upper()
                    if scheme in ("U", "X", "M"):
                        zmk_len = 33
                    elif scheme in ("T", "Y"):
                        zmk_len = 49
                    elif scheme in ("D", "A"):
                        zmk_len = 33 if len(rem) >= 33 else 17
                    elif scheme == "E":
                        zmk_len = 49 if len(rem) >= 49 else (33 if len(rem) >= 33 else 17)
                    elif scheme == "Z":
                        zmk_len = 17
                    else:
                        zmk_len = 48 if len(rem) >= 48 and all(chr(c) in string.hexdigits for c in rem[:48]) else 32
                offset = zmk_len
                lmk_fmt = rem[offset:offset + 2]
                key_len_field = rem[offset + 4:offset + 8]
                offset += 8
                if lmk_fmt == b"04":
                    if rem[offset:offset + 1] in (b"S", b"R"):
                        kb_len = 1 + int(rem[offset + 2:offset + 6].decode("ascii"))
                    else:
                        kb_len = int(rem[offset + 1:offset + 5].decode("ascii"))
                    offset += kb_len
                else:
                    key_len = int(key_len_field.decode("ascii"))
                    offset += key_len
                delim_pos = rem.find(b"\x19", offset)
            except Exception:
                delim_pos = -1
        elif command_code == "LY" and len(rem) >= 8:
            try:
                in_fmt = rem[:2]
                key_len_field = rem[4:8]
                offset = 8
                if in_fmt == b"04":
                    if rem[offset:offset + 1] in (b"S", b"R"):
                        kb_len = 1 + int(rem[offset + 2:offset + 6].decode("ascii"))
                    else:
                        kb_len = int(rem[offset + 1:offset + 5].decode("ascii"))
                    offset += kb_len
                else:
                    key_len = int(key_len_field.decode("ascii"))
                    offset += key_len
                delim_pos = rem.find(b"\x19", offset)
            except Exception:
                delim_pos = -1
        else:
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

        Response data is supplied by the command handler.  Some payShield errors
        include command-specific diagnostic fields, so framing must not discard it.
        """
        resp_str = response_code.decode("ascii", errors="ignore") if isinstance(response_code, bytes) else str(response_code)
        err_str = error_code.decode("ascii", errors="ignore") if isinstance(error_code, bytes) else str(error_code)

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
