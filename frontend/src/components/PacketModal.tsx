import { Connection } from '../types'

interface Props {
  connection: Connection
  onClose: () => void
}

export default function PacketModal({ connection, onClose }: Props) {
  const { src_ip, dst_ip, protocol, src_port, dst_port, packets } = connection
  const sorted = [...packets].sort((a, b) => a.timestamp - b.timestamp)

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: '#fff', borderRadius: 8, padding: 24,
          maxWidth: 800, width: '90%', maxHeight: '80vh',
          display: 'flex', flexDirection: 'column', gap: 12,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <strong>{src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})</strong>
          <button onClick={onClose}>✕ Close</button>
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thStyle}>#</th>
                <th style={thStyle}>Source IP</th>
                <th style={thStyle}>Destination IP</th>
                <th style={thStyle}>Timestamp</th>
                <th style={thStyle}>Length (bytes)</th>
                <th style={thStyle}>TCP Flags</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((pkt, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? '#f9f9f9' : '#fff' }}>
                  <td style={tdStyle}>{pkt.packet_number}</td>
                  <td style={tdStyle}>{pkt.src_ip}</td>
                  <td style={tdStyle}>{pkt.dst_ip}</td>
                  <td style={tdStyle}>{new Date(pkt.timestamp * 1000).toISOString()}</td>
                  <td style={tdStyle}>{pkt.length}</td>
                  <td style={tdStyle}>{pkt.tcp_flags ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '6px 8px',
  borderBottom: '2px solid #ccc', background: '#f0f0f0',
}
const tdStyle: React.CSSProperties = {
  padding: '4px 8px', borderBottom: '1px solid #eee',
}
