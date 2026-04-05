import { useRef, useState } from 'react'
import { Connection } from '../types'

interface UploadFormProps {
  onResult: (connections: Connection[]) => void
  onError: (message: string) => void
  onLoadingChange: (loading: boolean) => void
}

const MAX_FILE_SIZE = 100 * 1024 * 1024

export default function UploadForm({ onResult, onError, onLoadingChange }: UploadFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(e.target.files?.[0] ?? null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFile) return
    if (selectedFile.size > MAX_FILE_SIZE) { onError('File exceeds the 100 MB size limit.'); return }
    const formData = new FormData()
    formData.append('file', selectedFile)
    onLoadingChange(true)
    try {
      const response = await fetch('/api/analyze', { method: 'POST', body: formData })
      const data = await response.json()
      if (!response.ok) onError(data.error)
      else onResult(data.connections)
    } catch {
      onError('Could not reach the server. Please try again.')
    } finally {
      onLoadingChange(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
      <label style={{
        display: 'inline-flex', alignItems: 'center', gap: 8,
        border: '1px solid #ccc', borderRadius: 5,
        padding: '6px 14px', cursor: 'pointer',
        background: '#f4f6f9', color: '#333', fontSize: 13,
      }}>
        📂 Choose File
        <input ref={inputRef} type="file" accept=".pcap,.pcapng" onChange={handleFileChange} style={{ display: 'none' }} />
      </label>
      {selectedFile && <span style={{ color: '#555', fontSize: 13 }}>{selectedFile.name}</span>}
      <button
        type="submit"
        disabled={!selectedFile}
        style={{
          padding: '6px 18px', borderRadius: 5,
          border: 'none',
          background: selectedFile ? '#1f6feb' : '#ccc',
          color: '#fff',
          cursor: selectedFile ? 'pointer' : 'not-allowed',
          fontWeight: 500, fontSize: 13,
        }}
      >
        Analyze
      </button>
    </form>
  )
}
