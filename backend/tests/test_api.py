"""Integration tests for POST /api/analyze endpoint."""
import struct
import socket
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.main import app

# ---------------------------------------------------------------------------
# Minimal pcap builder (duplicated here to keep tests self-contained)
# ---------------------------------------------------------------------------

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,
)


def _pcap_record(raw: bytes) -> bytes:
    return struct.pack("<IIII", 0, 0, len(raw), len(raw)) + raw


def _eth_ip_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 65535, 0, 0)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, src, dst)
    eth = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x00"
    return eth + ip + tcp


def _valid_pcap() -> bytes:
    pkt = _eth_ip_tcp_packet("192.168.1.1", "10.0.0.1", 12345, 80)
    return _PCAP_GLOBAL_HEADER + _pcap_record(pkt)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_pcap_upload_returns_200_with_connections():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/analyze",
            files={"file": ("capture.pcap", _valid_pcap(), "application/octet-stream")},
        )
    assert response.status_code == 200
    body = response.json()
    assert "connections" in body
    assert isinstance(body["connections"], list)
    assert len(body["connections"]) >= 1


@pytest.mark.asyncio
async def test_invalid_file_bytes_returns_400_with_error_key():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/analyze",
            files={"file": ("bad.pcap", b"\x00\x01\x02\x03\x04\x05\x06\x07", "application/octet-stream")},
        )
    assert response.status_code == 400
    body = response.json()
    assert "error" in body


@pytest.mark.asyncio
async def test_no_authorization_header_required():
    """Endpoint must succeed without any Authorization header."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/analyze",
            files={"file": ("capture.pcap", _valid_pcap(), "application/octet-stream")},
            # Deliberately no Authorization header
        )
    assert response.status_code == 200
