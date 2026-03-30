"""Unit tests for backend/parser.py"""
import struct
import socket
import pytest

from backend.parser import parse
from backend.models import TerminationReason

# ---------------------------------------------------------------------------
# Helpers to build minimal synthetic pcap bytes
# ---------------------------------------------------------------------------

# pcap global header: magic, version_major, version_minor, thiszone,
#                     sigfigs, snaplen, network (1 = Ethernet)
_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic (little-endian)
    2, 4,        # version
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # network: Ethernet
)


def _pcap_record(raw_packet: bytes) -> bytes:
    """Wrap raw packet bytes in a pcap record header."""
    ts_sec = 0
    ts_usec = 0
    incl_len = len(raw_packet)
    orig_len = len(raw_packet)
    return struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len) + raw_packet


def _eth_ip_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = 0,
) -> bytes:
    """Build a minimal Ethernet + IPv4 + TCP packet."""
    # TCP segment (20 bytes, no payload)
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,   # sport
        dst_port,   # dport
        0,          # seq
        0,          # ack
        0x50,       # data offset (5 * 4 = 20 bytes), reserved
        flags,      # flags
        65535,      # window
        0,          # checksum (not validated by dpkt parser)
        0,          # urgent pointer
    )

    # IPv4 header (20 bytes)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    total_len = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,       # version + IHL
        0,          # DSCP/ECN
        total_len,
        0,          # identification
        0,          # flags + fragment offset
        64,         # TTL
        6,          # protocol: TCP
        0,          # checksum
        src,
        dst,
    )

    # Ethernet frame (14 bytes)
    eth = b"\xff\xff\xff\xff\xff\xff"  # dst MAC
    eth += b"\x00\x00\x00\x00\x00\x00"  # src MAC
    eth += b"\x08\x00"  # EtherType: IPv4

    return eth + ip + tcp


def _eth_ip_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    """Build a minimal Ethernet + IPv4 + UDP packet."""
    # UDP header (8 bytes)
    udp = struct.pack("!HHHH", src_port, dst_port, 8, 0)

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    total_len = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64,
        17,  # protocol: UDP
        0, src, dst,
    )

    eth = b"\xff\xff\xff\xff\xff\xff"
    eth += b"\x00\x00\x00\x00\x00\x00"
    eth += b"\x08\x00"

    return eth + ip + udp


def _build_pcap(*packets: bytes) -> bytes:
    """Combine global header + one record per packet."""
    records = b"".join(_pcap_record(p) for p in packets)
    return _PCAP_GLOBAL_HEADER + records


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidMinimalPcap:
    def test_single_tcp_connection_returns_one_connection(self):
        pkt = _eth_ip_tcp_packet("1.2.3.4", "5.6.7.8", 1234, 80)
        data = _build_pcap(pkt)
        conns = parse(data)
        assert len(conns) == 1
        c = conns[0]
        assert c.src_ip == "1.2.3.4"
        assert c.dst_ip == "5.6.7.8"
        assert c.protocol == "TCP"
        assert c.src_port == 1234
        assert c.dst_port == 80

    def test_duplicate_packets_deduplicated(self):
        pkt = _eth_ip_tcp_packet("1.2.3.4", "5.6.7.8", 1234, 80)
        data = _build_pcap(pkt, pkt, pkt)
        conns = parse(data)
        assert len(conns) == 1

    def test_two_distinct_flows_returns_two_connections(self):
        pkt1 = _eth_ip_tcp_packet("1.1.1.1", "2.2.2.2", 100, 80)
        pkt2 = _eth_ip_tcp_packet("3.3.3.3", "4.4.4.4", 200, 443)
        data = _build_pcap(pkt1, pkt2)
        conns = parse(data)
        assert len(conns) == 2


class TestInvalidBytes:
    def test_random_bytes_raise_value_error(self):
        with pytest.raises(ValueError):
            parse(b"\x00\x01\x02\x03\x04\x05\x06\x07")

    def test_empty_bytes_raise_value_error(self):
        with pytest.raises(ValueError):
            parse(b"")

    def test_truncated_header_raises_value_error(self):
        with pytest.raises(ValueError):
            parse(b"\xd4\xc3")


class TestTcpTermination:
    # TH_FIN = 0x01, TH_RST = 0x04
    FIN = 0x01
    RST = 0x04

    def _single_flow_pcap(self, *flag_list) -> bytes:
        packets = [
            _eth_ip_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 80, flags=f)
            for f in flag_list
        ]
        return _build_pcap(*packets)

    def test_fin_only_flow_is_fin(self):
        data = self._single_flow_pcap(self.FIN)
        conns = parse(data)
        assert conns[0].tcp_termination == TerminationReason.FIN

    def test_rst_only_flow_is_rst(self):
        data = self._single_flow_pcap(self.RST)
        conns = parse(data)
        assert conns[0].tcp_termination == TerminationReason.RST

    def test_rst_and_fin_flow_is_rst(self):
        data = self._single_flow_pcap(self.FIN, self.RST)
        conns = parse(data)
        assert conns[0].tcp_termination == TerminationReason.RST

    def test_no_fin_no_rst_is_timeout(self):
        data = self._single_flow_pcap(0x00)
        conns = parse(data)
        assert conns[0].tcp_termination == TerminationReason.TIMEOUT


class TestNonTcpProtocol:
    def test_udp_has_no_tcp_termination(self):
        pkt = _eth_ip_udp_packet("1.2.3.4", "5.6.7.8", 9999, 53)
        data = _build_pcap(pkt)
        conns = parse(data)
        assert len(conns) == 1
        assert conns[0].protocol == "UDP"
        assert conns[0].tcp_termination is None


class TestEmptyPcap:
    def test_empty_pcap_returns_empty_list(self):
        data = _PCAP_GLOBAL_HEADER  # valid header, zero packets
        conns = parse(data)
        assert conns == []
