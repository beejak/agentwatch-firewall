"""
MCP stdio framing: NDJSON (legacy) and Content-Length (MCP standard).

Wire format (MCP):
  Content-Length: <nbytes>\\r\\n
  \\r\\n
  <nbytes bytes of UTF-8 JSON>

Auto-detect: if a read starts with ``Content-Length:`` (case-insensitive), use
CL framing; otherwise treat as NDJSON (one JSON object per line).
"""
from __future__ import annotations

import json
from typing import Optional


def encode_cl_message(obj: dict) -> bytes:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def encode_ndjson_message(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


def detect_framing(sample: bytes) -> str:
    """Return 'cl' or 'ndjson' from the start of a buffer."""
    s = sample.lstrip()
    if s.lower().startswith(b"content-length:"):
        return "cl"
    return "ndjson"


async def read_message(reader) -> Optional[bytes]:
    """Read one JSON-RPC payload (raw JSON bytes) from an asyncio StreamReader.

    Returns None on EOF. Raises ValueError on malformed Content-Length framing.
    """
    first = await reader.readline()
    if not first:
        return None
    if first.lower().startswith(b"content-length:"):
        return await _finish_cl(reader, first)
    # NDJSON: strip trailing newline(s)
    line = first.rstrip(b"\r\n")
    return line if line else None


async def _finish_cl(reader, first_line: bytes) -> bytes:
    headers = [first_line]
    while True:
        line = await reader.readline()
        if not line:
            raise ValueError("EOF while reading MCP headers")
        headers.append(line)
        if line in (b"\r\n", b"\n"):
            break
    length = None
    for h in headers:
        if h.lower().startswith(b"content-length:"):
            try:
                length = int(h.split(b":", 1)[1].strip())
            except ValueError as e:
                raise ValueError(f"bad Content-Length: {h!r}") from e
    if length is None:
        raise ValueError("Content-Length header missing")
    if length < 0 or length > 50_000_000:
        raise ValueError(f"Content-Length out of range: {length}")
    return await reader.readexactly(length)
