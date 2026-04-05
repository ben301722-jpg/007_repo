export interface Packet {
  timestamp: number
  length: number
  src_ip: string
  dst_ip: string
  packet_number: number
  tcp_flags: string | null
  http_method: string | null
  http_uri: string | null
  dns_query: string | null
  dns_type: string | null
  dns_response: string | null
}

export interface Connection {
  src_ip: string
  dst_ip: string
  protocol: string
  src_port: number
  dst_port: number
  tcp_termination: 'FIN' | 'RST' | 'Timeout' | null
  packet_count: number
  packets: Packet[]
  http_method: string | null
  http_uri: string | null
  dns_query: string | null
  dns_type: string | null
  dns_response: string | null
}

export interface AnalyzeResponse {
  connections: Connection[]
}

export interface AnalyzeError {
  error: string
}
