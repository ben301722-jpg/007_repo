import { useRef, useState } from 'react'
import { Connection } from '../types'

interface UploadFormProps {
  onResult: (connections: Connection[]) => void
  onError: (message: string) => void
  onLoadingChange: (loading: boolean) => void
}

const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100 MB

export default function UploadForm({ onResult, onError, onLoadingChange }: UploadFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(e.target.files?.[0] ?? null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!selectedFile) return

    if (selectedFile.size > MAX_FILE_SIZE) {
      onError('File exceeds the 100 MB size limit.')
      return
    }

    const formData = new FormData()
    formData.append('file', selectedFile)

    onLoadingChange(true)
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        onError(data.error)
      } else {
        onResult(data.connections)
      }
    } catch {
      onError('Could not reach the server. Please try again.')
    } finally {
      onLoadingChange(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        onChange={handleFileChange}
      />
      <button type="submit" disabled={!selectedFile}>
        Analyze
      </button>
    </form>
  )
}
