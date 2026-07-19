"""Framing unit tests — no subprocess."""
import asyncio
import json

import pytest

from tracewall.transports.mcp_framing import (
    detect_framing,
    encode_cl_message,
    encode_ndjson_message,
    read_message,
)


def test_encode_cl_roundtrip_headers():
    obj = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    wire = encode_cl_message(obj)
    assert wire.lower().startswith(b"content-length:")
    assert b"\r\n\r\n" in wire
    body = wire.split(b"\r\n\r\n", 1)[1]
    assert json.loads(body) == obj
    assert detect_framing(wire) == "cl"


def test_encode_ndjson():
    obj = {"a": 1}
    assert encode_ndjson_message(obj) == b'{"a": 1}\n'
    assert detect_framing(b'{"a":1}\n') == "ndjson"


@pytest.mark.asyncio
async def test_read_cl_message():
    obj = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    wire = encode_cl_message(obj)
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    raw = await read_message(reader)
    assert json.loads(raw) == obj


@pytest.mark.asyncio
async def test_read_ndjson_message():
    reader = asyncio.StreamReader()
    reader.feed_data(b'{"x": true}\n')
    reader.feed_eof()
    raw = await read_message(reader)
    assert json.loads(raw) == {"x": True}
