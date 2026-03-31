import { useState } from 'react'
import { Connection } from '../types'
import PacketModal from './PacketModal'

interface Props {
  connections: Connection[]
}

type SortDir = 'asc' | 'desc' | null

const columns: { label: string; key: keyof Connection }[] = [
  { label: 'Source IP', key: 'src_ip' },
  { label: 'Destination IP', key: 'dst_ip' },
  { label: 'Protocol', key: 'protocol' },
  { label: 'Source Port', key: 'src_port' },
  { label: 'Destination Port', key: 'dst_port' },
  { label: 'TCP Termination', key: 'tcp_termination' },
  { label: 'Packets', key: 'packet_count' },
]

const ROW_EVEN = '#dce6f1'   // darker blue  (Excel-style)
const ROW_ODD  = '#eef3fb'   // lighter blue

const thStyle: React.CSSProperties = {
  padding: '10px 12px',
  background: '#1f4e79',
  color: '#fff',
  cursor: 'pointer',
  userSelect: 'none',
  whiteSpace: 'nowrap',
  borderRight: '1px solid #16375a',
}

const tdStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderBottom: '1px solid #b8cce4',
  borderRight: '1px solid #b8cce4',
  fontSize: 14,
}

export default function ConnectionTable({ connections }: Props) {
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [hostFilter, setHostFilter] = useState('')
  const [sortKey, setSortKey] = useState<keyof Connection | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>(null)
  const [selectedConn, setSelectedConn] = useState<Connection | null>(null)

  const handleFilter = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }))
  }

  const handleSort = (key: keyof Connection) => {
    if (sortKey !== key) {
      setSortKey(key); setSortDir('asc')
    } else {
      if (sortDir === 'asc') setSortDir('desc')
      else { setSortDir(null); setSortKey(null) }
    }
  }

  const sortIcon = (key: keyof Connection) => {
    if (sortKey !== key) return ' ⇅'
    return sortDir === 'asc' ? ' ↑' : ' ↓'
  }

  const filtered = connections.filter(conn => {
    if (hostFilter) {
      const h = hostFilter.toLowerCase()
      if (!conn.src_ip.toLowerCase().includes(h) && !conn.dst_ip.toLowerCase().includes(h))
        return false
    }
    return columns.every(({ key }) => {
      const f = filters[key]?.toLowerCase() ?? ''
      if (!f) return true
      return String(conn[key] ?? '').toLowerCase().includes(f)
    })
  })

  const sorted = sortKey && sortDir
    ? [...filtered].sort((a, b) => {
        const av = a[sortKey] ?? ''
        const bv = b[sortKey] ?? ''
        const cmp = typeof av === 'number' && typeof bv === 'number'
          ? av - bv : String(av).localeCompare(String(bv))
        return sortDir === 'asc' ? cmp : -cmp
      })
    : filtered

  if (connections.length === 0) return <p>No connections found.</p>

  return (
    <div>
      {selectedConn && (
        <PacketModal connection={selectedConn} onClose={() => setSelectedConn(null)} />
      )}
      <div style={{ marginBottom: 10 }}>
        <label style={{ fontWeight: 600 }}>
          Host IP filter:{' '}
          <input
            type="text"
            placeholder="e.g. 1.1.1.1"
            value={hostFilter}
            onChange={e => setHostFilter(e.target.value)}
            style={{ padding: '4px 8px', borderRadius: 4, border: '1px solid #aaa' }}
          />
        </label>
      </div>
      <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 14 }}>
        <thead>
          <tr>
            {columns.map(({ label, key }) => (
              <th key={key} style={thStyle} onClick={() => handleSort(key)}>
                {label}{sortIcon(key)}
              </th>
            ))}
          </tr>
          <tr style={{ background: '#2e6099' }}>
            {columns.map(({ key }) => (
              <th key={key} style={{ padding: '4px 6px' }}>
                <input
                  type="text"
                  placeholder="Filter..."
                  value={filters[key] ?? ''}
                  onChange={e => handleFilter(key, e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '3px 6px', borderRadius: 3, border: 'none', fontSize: 12 }}
                />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr><td colSpan={columns.length} style={{ padding: 12 }}>No matching connections.</td></tr>
          ) : (
            sorted.map((conn, index) => (
              <tr
                key={index}
                onClick={() => setSelectedConn(conn)}
                style={{ background: index % 2 === 0 ? ROW_EVEN : ROW_ODD, cursor: 'pointer' }}
                onMouseEnter={e => (e.currentTarget.style.filter = 'brightness(0.93)')}
                onMouseLeave={e => (e.currentTarget.style.filter = '')}
              >
                {columns.map(({ key }) => {
                  const isAlert = key === 'tcp_termination' &&
                    (conn.tcp_termination === 'RST' || conn.tcp_termination === 'Timeout')
                  return (
                    <td key={key} style={{ ...tdStyle, ...(isAlert ? { background: '#f4cccc', fontWeight: 700, color: '#a00' } : {}) }}>
                      {conn[key] ?? ''}
                    </td>
                  )
                })}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
