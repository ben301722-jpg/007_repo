import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import UploadForm from '../components/UploadForm'

describe('UploadForm', () => {
  const onResult = vi.fn()
  const onError = vi.fn()
  const onLoadingChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('file input has accept=".pcap,.pcapng"', () => {
    render(<UploadForm onResult={onResult} onError={onError} onLoadingChange={onLoadingChange} />)
    const input = screen.getByRole('button', { hidden: true })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).not.toBeNull()
    expect(fileInput.accept).toBe('.pcap,.pcapng')
  })

  it('calls onError with size limit message when file exceeds 100MB', async () => {
    const mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)

    render(<UploadForm onResult={onResult} onError={onError} onLoadingChange={onLoadingChange} />)

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    const largeFile = new File(['x'], 'large.pcap', { type: 'application/octet-stream' })
    Object.defineProperty(largeFile, 'size', { value: 101 * 1024 * 1024 })

    await userEvent.upload(fileInput, largeFile)

    const submitButton = screen.getByRole('button', { name: /analyze/i })
    await userEvent.click(submitButton)

    expect(onError).toHaveBeenCalledWith('File exceeds the 100 MB size limit.')
    expect(mockFetch).not.toHaveBeenCalled()

    vi.unstubAllGlobals()
  })
})
