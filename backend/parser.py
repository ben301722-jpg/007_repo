import dpkt
import socket
from io import BytesIO
from typing import List

from .models import Connection, Packet, TerminationReason

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


# DNS record type number → name
_DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY',
}


def _parse_dns(payload: bytes):
    """Parse a DNS UDP payload. Returns (query_name, record_type, response) or (None, None, None)."""
    try:
        dns = dpkt.dns.DNS(payload)
    except Exception:
        return None, None, None

    query_name = None
    record_type = None
    response = None

    if dns.qd:
        q = dns.qd[0]
        query_name = q.name
        record_type = _DNS_TYPES.get(q.type, str(q.type))

    # Only responses (QR flag set) carry answers
    if dns.qr == dpkt.dns.DNS_R and dns.an:
        answers = []
        for rr in dns.an:
            rtype = _DNS_TYPES.get(rr.type, str(rr.type))
            try:
                if rr.type == dpkt.dns.DNS_A:
                    answers.append(socket.inet_ntoa(rr.rdata))
                elif rr.type == dpkt.dns.DNS_AAAA:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rr.rdata))
                elif rr.type in (dpkt.dns.DNS_CNAME, dpkt.dns.DNS_PTR, dpkt.dns.DNS_NS):
                    answers.append(rr.cname if hasattr(rr, 'cname') else rr.rdata.decode('utf-8', errors='ignore'))
                elif rr.type == dpkt.dns.DNS_MX:
                    answers.append(rr.mxname if hasattr(rr, 'mxname') else str(rr.rdata))
                else:
                    answers.append(f'[{rtype}]')
            except Exception:
                answers.append(f'[{rtype}]')
        response = ', '.join(answers) if answers else None

    return query_name, record_type, response


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
        global_pkt_num = 0

        for ts, raw in reader:
            global_pkt_num += 1
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
            # Use canonical key so both directions map to the same flow
            rev_key = (dst_ip, src_ip, proto_num, dst_port, src_port)
            if rev_key in connection_map:
                key = rev_key
            elif key not in connection_map:
                connection_map[key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto_num': proto_num,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'seen_fin': False,
                    'seen_rst': False,
                    'packet_count': 0,
                    'packets': [],
                }

            connection_map[key]['packet_count'] += 1

            # Parse HTTP method and URI from TCP payload (ports 80 or 443)
            http_method = None
            http_uri = None
            if proto_num == 6 and isinstance(transport, dpkt.tcp.TCP):
                payload = bytes(transport.data)
                if payload:
                    try:
                        first_line = payload.split(b'\r\n', 1)[0].decode('utf-8', errors='ignore')
                        parts = first_line.split(' ')
                        http_methods = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}
                        if len(parts) >= 2 and parts[0] in http_methods:
                            http_method = parts[0]
                            http_uri = parts[1]
                    except Exception:
                        pass

            # Parse DNS from UDP port 53
            dns_query = None
            dns_type = None
            dns_response = None
            if proto_num == 17 and isinstance(transport, dpkt.udp.UDP):
                if transport.sport == 53 or transport.dport == 53:
                    dns_query, dns_type, dns_response = _parse_dns(bytes(transport.data))

            # Build TCP flags string
            tcp_flags = None
            if proto_num == 6 and isinstance(transport, dpkt.tcp.TCP):
                flags = transport.flags
                flag_parts = []
                if flags & dpkt.tcp.TH_SYN: flag_parts.append('SYN')
                if flags & dpkt.tcp.TH_ACK: flag_parts.append('ACK')
                if flags & dpkt.tcp.TH_FIN: flag_parts.append('FIN')
                if flags & dpkt.tcp.TH_RST: flag_parts.append('RST')
                if flags & dpkt.tcp.TH_PUSH: flag_parts.append('PSH')
                if flags & dpkt.tcp.TH_URG: flag_parts.append('URG')
                tcp_flags = '+'.join(flag_parts) if flag_parts else '—'

            # Track TCP termination flags
            if proto_num == 6 and isinstance(transport, dpkt.tcp.TCP):
                flags = transport.flags
                if flags & dpkt.tcp.TH_RST:
                    connection_map[key]['seen_rst'] = True
                if flags & dpkt.tcp.TH_FIN:
                    connection_map[key]['seen_fin'] = True

            connection_map[key]['packets'].append(Packet(
                timestamp=float(ts),
                length=len(raw),
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_number=global_pkt_num,
                tcp_flags=tcp_flags,
                http_method=http_method,
                http_uri=http_uri,
                dns_query=dns_query,
                dns_type=dns_type,
                dns_response=dns_response,
            ))
            # Store first HTTP request seen on this connection
            if http_method and not connection_map[key].get('http_method'):
                connection_map[key]['http_method'] = http_method
                connection_map[key]['http_uri'] = http_uri
            # Store DNS query (from query packet) and response (from response packet)
            if dns_query and not connection_map[key].get('dns_query'):
                connection_map[key]['dns_query'] = dns_query
                connection_map[key]['dns_type'] = dns_type
            if dns_response and not connection_map[key].get('dns_response'):
                connection_map[key]['dns_response'] = dns_response

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
                packet_count=flow['packet_count'],
                packets=flow['packets'],
                http_method=flow.get('http_method'),
                http_uri=flow.get('http_uri'),
                dns_query=flow.get('dns_query'),
                dns_type=flow.get('dns_type'),
                dns_response=flow.get('dns_response'),
            ))

        return connections


def parse(data: bytes) -> List[Connection]:
    """Main entry point: parse pcap/pcapng bytes and return connections."""
    return PcapParser().parse(data)
