from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class TerminationReason(str, Enum):
    FIN = "FIN"
    RST = "RST"
    TIMEOUT = "Timeout"


@dataclass
class Packet:
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    packet_number: int        # 1-based index in the pcap file
    tcp_flags: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    dns_response: Optional[str] = None


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    tcp_termination: Optional[TerminationReason] = None
    packet_count: int = 0
    packets: List[Packet] = field(default_factory=list)
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    dns_response: Optional[str] = None
