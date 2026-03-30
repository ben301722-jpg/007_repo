import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import ConnectionTable from '../components/ConnectionTable'
import { Connection } from '../types'

const baseConnection: Connection = {
  src_ip: '192.168.1.1',
  dst_ip: '10.0.0.1',
  protocol: 'TCP',
  src_port: 12345,
  dst_port: 80,
  tcp_termination: 'FIN',
}

describe('ConnectionTable', () => {
  it('renders "No connections found." when connections array is empty', () => {
    render(<ConnectionTable connections={[]} />)
    expect(screen.getByText('No connections found.')).toBeInTheDocument()
  })

  it('renders empty cell when tcp_termination is null', () => {
    const conn: Connection = { ...baseConnection, protocol: 'UDP', tcp_termination: null }
    render(<ConnectionTable connections={[conn]} />)
    const cells = screen.getAllByRole('cell')
    // TCP Termination is the 6th column (index 5)
    expect(cells[5].textContent).toBe('')
  })

  it('renders "FIN" for a TCP connection with FIN termination', () => {
    const conn: Connection = { ...baseConnection, tcp_termination: 'FIN' }
    render(<ConnectionTable connections={[conn]} />)
    expect(screen.getByText('FIN')).toBeInTheDocument()
  })

  it('renders "RST" for a TCP connection with RST termination', () => {
    const conn: Connection = { ...baseConnection, tcp_termination: 'RST' }
    render(<ConnectionTable connections={[conn]} />)
    expect(screen.getByText('RST')).toBeInTheDocument()
  })

  it('renders "Timeout" for a TCP connection with Timeout termination', () => {
    const conn: Connection = { ...baseConnection, tcp_termination: 'Timeout' }
    render(<ConnectionTable connections={[conn]} />)
    expect(screen.getByText('Timeout')).toBeInTheDocument()
  })

  it('renders all 5 base columns with correct values', () => {
    render(<ConnectionTable connections={[baseConnection]} />)
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('TCP')).toBeInTheDocument()
    expect(screen.getByText('12345')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
  })
})
