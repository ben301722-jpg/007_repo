from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TerminationReason(str, Enum):
    FIN = "FIN"
    RST = "RST"
    TIMEOUT = "Timeout"


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    tcp_termination: Optional[TerminationReason] = None
