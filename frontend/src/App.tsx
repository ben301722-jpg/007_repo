import { useState } from 'react'
import { Connection } from './types'
import UploadForm from './components/UploadForm'
import LoadingIndicator from './components/LoadingIndicator'
import ErrorBanner from './components/ErrorBanner'
import ConnectionTable from './components/ConnectionTable'

export default function App() {
  const [connections, setConnections] = useState<Connection[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleResult = (data: Connection[]) => { setConnections(data); setError(null) }
  const handleError = (message: string) => { setError(message); setConnections([]) }
  const handleUploadStart = () => { setError(null); setConnections([]) }

  return (
    <div style={{ minHeight: '100vh', background: '#f4f6f9' }}>
      <header style={{
        background: '#fff',
        borderBottom: '1px solid #dde3ea',
        padding: '0 28px',
        height: 52,
        display: 'flex',
        alignItems: 'center',
        gap: 10,
      }}>
        <span style={{ fontWeight: 600, fontSize: 16, color: '#1a1a2e' }}>PCAP Analyzer</span>
        <span style={{ color: '#aaa', fontSize: 12 }}>Network Traffic Inspector</span>
      </header>

      <main style={{ padding: '24px 28px' }}>
        <div style={{
          background: '#fff', border: '1px solid #dde3ea',
          borderRadius: 8, padding: '20px 24px', marginBottom: 20,
        }}>
          <UploadForm
            onResult={handleResult}
            onError={handleError}
            onLoadingChange={(loading) => { if (loading) handleUploadStart(); setIsLoading(loading) }}
          />
          <LoadingIndicator isLoading={isLoading} />
          <ErrorBanner message={error} />
        </div>

        {connections.length > 0 && (
          <div style={{ background: '#fff', border: '1px solid #dde3ea', borderRadius: 8, padding: '20px 24px' }}>
            <div style={{ color: '#666', fontSize: 12, marginBottom: 14, textTransform: 'uppercase', letterSpacing: 1 }}>
              Connections — {connections.length} found
            </div>
            <ConnectionTable connections={connections} />
          </div>
        )}
      </main>
    </div>
  )
}
