import { Connection } from '../types'

interface Props {
  connection: Connection
  onClose: () => void
}

const headers = ['#', 'Source IP', 'Destination IP', 'Timestamp', 'Length', 'TCP Flags',
  'HTTP Method', 'HTTP URI', 'DNS Query', 'DNS Type', 'DNS Response']

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '7px 10px',
  background: '#f0f0f0', borderBottom: '2px solid #ccc',
  borderRight: '1px solid #ddd', fontSize: 12, whiteSpace: 'nowrap',
}

const tdStyle: React.CSSProperties = {
  padding: '6px 10px', borderBottom: '1px solid #eee',
  borderRight: '1px solid #eee', fontSize: 12, whiteSpace: 'nowrap',
}

export default function PacketModal({ connection, onClose }: Props) {
  const { src_ip, dst_ip, protocol, src_port, dst_port, packets } = connection
  const sorted = [...packets].sort((a, b) => a.timestamp - b.timestamp)

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: '#fff', borderRadius: 8, padding: 24,
          maxWidth: 1100, width: '95%', maxHeight: '85vh',
          display: 'flex', flexDirection: 'column', gap: 12,
          boxShadow: '0 8px 32px rgba(0,0,0,0.18)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>
            {src_ip}:{src_port} → {dst_ip}:{dst_port}
            <span style={{ marginLeft: 8, background: '#e8f0fe', color: '#1a73e8', borderRadius: 4, padding: '2px 8px', fontSize: 12 }}>
              {protocol}
            </span>
            <span style={{ marginLeft: 8, color: '#888', fontSize: 12, fontWeight: 400 }}>{sorted.length} packets</span>
          </span>
          <button
            onClick={onClose}
            style={{ background: '#fff', border: '1px solid #ccc', borderRadius: 5, padding: '5px 14px', cursor: 'pointer', fontSize: 13 }}
          >
            ✕ Close
          </button>
        </div>

        <div style={{ overflowY: 'auto', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>{headers.map(h => <th key={h} style={thStyle}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {sorted.map((pkt, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? '#f9f9f9' : '#fff' }}>
                  {[
                    pkt.packet_number, pkt.src_ip, pkt.dst_ip,
                    new Date(pkt.timestamp * 1000).toISOString(),
                    pkt.length, pkt.tcp_flags ?? '—',
                    pkt.http_method ?? '—', pkt.http_uri ?? '—',
                    pkt.dns_query ?? '—', pkt.dns_type ?? '—', pkt.dns_response ?? '—',
                  ].map((val, j) => <td key={j} style={tdStyle}>{val}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
