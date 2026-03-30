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

  const handleResult = (data: Connection[]) => {
    setConnections(data)
    setError(null)
  }

  const handleError = (message: string) => {
    setError(message)
    setConnections([])
  }

  const handleUploadStart = () => {
    setError(null)
    setConnections([])
  }

  return (
    <div>
      <h1>PCAP Analyzer</h1>
      <UploadForm
        onResult={handleResult}
        onError={handleError}
        onLoadingChange={(loading) => {
          if (loading) handleUploadStart()
          setIsLoading(loading)
        }}
      />
      <LoadingIndicator isLoading={isLoading} />
      <ErrorBanner message={error} />
      <ConnectionTable connections={connections} />
    </div>
  )
}
