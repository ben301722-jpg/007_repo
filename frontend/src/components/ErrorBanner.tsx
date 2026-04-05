interface ErrorBannerProps {
  message: string | null
}

export default function ErrorBanner({ message }: ErrorBannerProps) {
  if (!message) return null
  return (
    <div role="alert" style={{
      marginTop: 12, padding: '9px 14px',
      border: '1px solid #f5c6cb', borderRadius: 5,
      background: '#fff5f5', color: '#c0392b', fontSize: 13,
    }}>
      ⚠ {message}
    </div>
  )
}
