"""
Minimal WebSocket frame encoder / decoder (RFC 6455).

Only handles binary (opcode 0x02) and close (opcode 0x08) frames.
Client-to-server frames are always masked as required by the spec.
"""

import os
import struct


def ws_encode(data: bytes, opcode: int = 0x02) -> bytes:
    """Encode *data* into a masked binary WebSocket frame."""
    head = bytearray([0x80 | opcode])  # FIN + opcode

    length = len(data)
    if length < 126:
        head.append(0x80 | length)
    elif length < 0x10000:
        head.append(0x80 | 126)
        head += struct.pack("!H", length)
    else:
        head.append(0x80 | 127)
        head += struct.pack("!Q", length)

    mask = os.urandom(4)
    head += mask

    masked = bytearray(data)
    for i in range(len(masked)):
        masked[i] ^= mask[i & 3]

    return bytes(head) + bytes(masked)


def ws_decode(buf: bytes):
    """Try to decode one frame from *buf*.

    Returns ``(opcode, payload, consumed_bytes)`` or ``None`` if the
    buffer does not yet contain a complete frame.
    """
    if len(buf) < 2:
        return None

    opcode = buf[0] & 0x0F
    is_masked = buf[1] & 0x80
    length = buf[1] & 0x7F
    pos = 2

    if length == 126:
        if len(buf) < 4:
            return None
        length = struct.unpack("!H", buf[2:4])[0]
        pos = 4
    elif length == 127:
        if len(buf) < 10:
            return None
        length = struct.unpack("!Q", buf[2:10])[0]
        pos = 10

    mask = None
    if is_masked:
        if len(buf) < pos + 4:
            return None
        mask = buf[pos : pos + 4]
        pos += 4

    if len(buf) < pos + length:
        return None

    payload = bytearray(buf[pos : pos + length])
    if mask:
        for i in range(len(payload)):
            payload[i] ^= mask[i & 3]

    return opcode, bytes(payload), pos + length
