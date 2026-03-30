import { Connection } from '../types'

interface Props {
  connections: Connection[]
}

export default function ConnectionTable({ connections }: Props) {
  if (connections.length === 0) {
    return <p>No connections found.</p>
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Source IP</th>
          <th>Destination IP</th>
          <th>Protocol</th>
          <th>Source Port</th>
          <th>Destination Port</th>
          <th>TCP Termination</th>
        </tr>
      </thead>
      <tbody>
        {connections.map((conn, index) => (
          <tr key={index}>
            <td>{conn.src_ip}</td>
            <td>{conn.dst_ip}</td>
            <td>{conn.protocol}</td>
            <td>{conn.src_port}</td>
            <td>{conn.dst_port}</td>
            <td>{conn.tcp_termination ?? ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
