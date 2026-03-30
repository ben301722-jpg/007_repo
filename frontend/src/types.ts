export interface Connection {
  src_ip: string
  dst_ip: string
  protocol: string
  src_port: number
  dst_port: number
  tcp_termination: 'FIN' | 'RST' | 'Timeout' | null
}

export interface AnalyzeResponse {
  connections: Connection[]
}

export interface AnalyzeError {
  error: string
}
