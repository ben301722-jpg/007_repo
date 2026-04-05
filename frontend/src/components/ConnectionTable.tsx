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
  { label: 'Src Port', key: 'src_port' },
  { label: 'Dst Port', key: 'dst_port' },
  { label: 'TCP Term.', key: 'tcp_termination' },
  { label: 'HTTP Method', key: 'http_method' },
  { label: 'HTTP URI', key: 'http_uri' },
  { label: 'DNS Query', key: 'dns_query' },
  { label: 'DNS Type', key: 'dns_type' },
  { label: 'DNS Response', key: 'dns_response' },
  { label: 'Packets', key: 'packet_count' },
]

const HTTP_KEYS: (keyof Connection)[] = ['http_method', 'http_uri']
const DNS_KEYS: (keyof Connection)[] = ['dns_query', 'dns_type', 'dns_response']

const ROW_EVEN = '#dce6f1'
const ROW_ODD  = '#eef3fb'

const thStyle: React.CSSProperties = {
  padding: '10px 12px',
  background: '#1f4e79',
  color: '#fff',
  cursor: 'pointer',
  userSelect: 'none',
  whiteSpace: 'nowrap',
  borderRight: '1px solid #16375a',
  fontSize: 13,
  textAlign: 'left',
}

const tdStyle: React.CSSProperties = {
  padding: '9px 12px',
  borderBottom: '1px solid #b8cce4',
  borderRight: '1px solid #b8cce4',
  fontSize: 13,
}

const controlInput: React.CSSProperties = {
  padding: '4px 8px', borderRadius: 4,
  border: '1px solid #ccc', background: '#fff',
  color: '#333', fontSize: 12, outline: 'none',
}

export default function ConnectionTable({ connections }: Props) {
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [hostFilter, setHostFilter] = useState('')
  const [trafficFilter, setTrafficFilter] = useState('')
  const [showHttp, setShowHttp] = useState(true)
  const [showDns, setShowDns] = useState(true)
  const [sortKey, setSortKey] = useState<keyof Connection | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>(null)
  const [selectedConn, setSelectedConn] = useState<Connection | null>(null)

  const visibleColumns = columns.filter(({ key }) => {
    if (HTTP_KEYS.includes(key) && !showHttp) return false
    if (DNS_KEYS.includes(key) && !showDns) return false
    return true
  })

  const handleFilter = (key: string, value: string) =>
    setFilters(prev => ({ ...prev, [key]: value }))

  const handleSort = (key: keyof Connection) => {
    if (sortKey !== key) { setSortKey(key); setSortDir('asc') }
    else if (sortDir === 'asc') setSortDir('desc')
    else { setSortDir(null); setSortKey(null) }
  }

  const sortIcon = (key: keyof Connection) => {
    if (sortKey !== key) return ' ⇅'
    return sortDir === 'asc' ? ' ↑' : ' ↓'
  }

  const filtered = connections.filter(conn => {
    if (hostFilter) {
      const h = hostFilter.toLowerCase()
      if (!conn.src_ip.toLowerCase().includes(h) && !conn.dst_ip.toLowerCase().includes(h)) return false
    }
    if (trafficFilter === 'http' && !conn.http_method) return false
    if (trafficFilter === 'https' && !(conn.dst_port === 443 || conn.src_port === 443)) return false
    if (trafficFilter === 'dns' && !conn.dns_query) return false
    return columns.every(({ key }) => {
      const f = filters[key]?.toLowerCase() ?? ''
      if (!f) return true
      return String(conn[key] ?? '').toLowerCase().includes(f)
    })
  })

  const sorted = sortKey && sortDir
    ? [...filtered].sort((a, b) => {
        const av = a[sortKey] ?? ''; const bv = b[sortKey] ?? ''
        const cmp = typeof av === 'number' && typeof bv === 'number'
          ? av - bv : String(av).localeCompare(String(bv))
        return sortDir === 'asc' ? cmp : -cmp
      })
    : filtered

  if (connections.length === 0) return null

  return (
    <div>
      {selectedConn && (
        <PacketModal connection={selectedConn} onClose={() => setSelectedConn(null)} />
      )}

      {/* Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', marginBottom: 12 }}>
        <label style={{ fontSize: 13, color: '#444', display: 'flex', alignItems: 'center', gap: 6 }}>
          Host IP
          <input type="text" placeholder="e.g. 1.1.1.1" value={hostFilter}
            onChange={e => setHostFilter(e.target.value)} style={controlInput} />
        </label>
        <label style={{ fontSize: 13, color: '#444', display: 'flex', alignItems: 'center', gap: 6 }}>
          Traffic
          <select value={trafficFilter} onChange={e => setTrafficFilter(e.target.value)} style={controlInput}>
            <option value=''>All</option>
            <option value='http'>HTTP</option>
            <option value='https'>HTTPS</option>
            <option value='dns'>DNS</option>
          </select>
        </label>
        <div style={{ width: 1, height: 18, background: '#ddd' }} />
        {[{ label: 'HTTP', val: showHttp, set: setShowHttp }, { label: 'DNS', val: showDns, set: setShowDns }].map(({ label, val, set }) => (
          <label key={label} style={{ fontSize: 13, color: '#444', display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
            <input type="checkbox" checked={val} onChange={e => set(e.target.checked)} />
            {label}
          </label>
        ))}
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 13 }}>
          <thead>
            <tr>
              {visibleColumns.map(({ label, key }) => (
                <th key={key} style={thStyle} onClick={() => handleSort(key)}>
                  {label}{sortIcon(key)}
                </th>
              ))}
            </tr>
            <tr style={{ background: '#2e6099' }}>
              {visibleColumns.map(({ key }) => (
                <th key={key} style={{ padding: '4px 6px' }}>
                  <input
                    type="text" placeholder="Filter..."
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
              <tr><td colSpan={visibleColumns.length} style={{ padding: 14, color: '#888', textAlign: 'center' }}>No matching connections.</td></tr>
            ) : (
              sorted.map((conn, index) => (
                <tr
                  key={index}
                  onClick={() => setSelectedConn(conn)}
                  style={{ background: index % 2 === 0 ? ROW_EVEN : ROW_ODD, cursor: 'pointer' }}
                  onMouseEnter={e => (e.currentTarget.style.filter = 'brightness(0.93)')}
                  onMouseLeave={e => (e.currentTarget.style.filter = '')}
                >
                  {visibleColumns.map(({ key }) => {
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
    </div>
  )
}
