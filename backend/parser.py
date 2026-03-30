import dpkt
import socket
from io import BytesIO
from typing import List

from .models import Connection, TerminationReason

# Magic bytes for format detection
_PCAP_MAGIC_LE = b'\xd4\xc3\xb2\xa1'
_PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'
_PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

# IANA protocol number → name lookup
_PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def _resolve_protocol(proto_num: int) -> str:
    return _PROTO_NAMES.get(proto_num, str(proto_num))


def _detect_format(data: bytes) -> str:
    """Return 'pcap', 'pcapng', or raise ValueError."""
    if len(data) < 4:
        raise ValueError("File too short to be a valid PCAP or PCAPNG file.")
    magic = data[:4]
    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE):
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        return "pcapng"
    raise ValueError(
        f"Unrecognised file format (magic bytes: {magic.hex()}). "
        "Expected a pcap or pcapng file."
    )


def _get_ports(transport) -> tuple[int, int]:
    """Extract (src_port, dst_port) from a transport-layer object, or (0, 0)."""
    if hasattr(transport, 'sport') and hasattr(transport, 'dport'):
        return transport.sport, transport.dport
    return 0, 0


class PcapParser:
    """Parse pcap/pcapng bytes and return a list of Connection objects."""

    def parse(self, data: bytes) -> List[Connection]:
        fmt = _detect_format(data)

        buf = BytesIO(data)
        if fmt == "pcap":
            reader = dpkt.pcap.Reader(buf)
        else:
            reader = dpkt.pcapng.Reader(buf)

        # connection_map: key → {'src_ip', 'dst_ip', 'proto_num', 'src_port',
        #                         'dst_port', 'seen_fin', 'seen_rst'}
        connection_map: dict = {}

        for _ts, raw in reader:
            # Try to unwrap Ethernet frame
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                ip_payload = eth.data
            except Exception:
                continue

            # Determine IP version and extract addresses
            if isinstance(ip_payload, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip_payload.src)
                dst_ip = socket.inet_ntoa(ip_payload.dst)
                proto_num = ip_payload.p
                transport = ip_payload.data
            elif isinstance(ip_payload, dpkt.ip6.IP6):
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_payload.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_payload.dst)
                proto_num = ip_payload.nxt
                transport = ip_payload.data
            else:
                # Non-IP frame — skip silently
                continue

            # Extract ports based on protocol
            if proto_num == 6:  # TCP
                if isinstance(transport, dpkt.tcp.TCP):
                    src_port, dst_port = transport.sport, transport.dport
                else:
                    src_port, dst_port = 0, 0
            elif proto_num == 17:  # UDP
                if isinstance(transport, dpkt.udp.UDP):
                    src_port, dst_port = transport.sport, transport.dport
                else:
                    src_port, dst_port = 0, 0
            else:
                # ICMP, ICMPv6, and all other protocols
                src_port, dst_port = 0, 0

            key = (src_ip, dst_ip, proto_num, src_port, dst_port)

            if key not in connection_map:
                connection_map[key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto_num': proto_num,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'seen_fin': False,
                    'seen_rst': False,
                }

            # Track TCP flags
            if proto_num == 6 and isinstance(transport, dpkt.tcp.TCP):
                flags = transport.flags
                if flags & dpkt.tcp.TH_RST:
                    connection_map[key]['seen_rst'] = True
                if flags & dpkt.tcp.TH_FIN:
                    connection_map[key]['seen_fin'] = True

        # Build Connection objects
        connections: List[Connection] = []
        for flow in connection_map.values():
            proto_num = flow['proto_num']
            protocol = _resolve_protocol(proto_num)

            if proto_num == 6:  # TCP
                if flow['seen_rst']:
                    termination = TerminationReason.RST
                elif flow['seen_fin']:
                    termination = TerminationReason.FIN
                else:
                    termination = TerminationReason.TIMEOUT
            else:
                termination = None

            connections.append(Connection(
                src_ip=flow['src_ip'],
                dst_ip=flow['dst_ip'],
                protocol=protocol,
                src_port=flow['src_port'],
                dst_port=flow['dst_port'],
                tcp_termination=termination,
            ))

        return connections


def parse(data: bytes) -> List[Connection]:
    """Main entry point: parse pcap/pcapng bytes and return connections."""
    return PcapParser().parse(data)
