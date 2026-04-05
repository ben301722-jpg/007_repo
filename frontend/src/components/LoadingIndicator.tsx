interface LoadingIndicatorProps {
  isLoading: boolean
}

export default function LoadingIndicator({ isLoading }: LoadingIndicatorProps) {
  if (!isLoading) return null
  return (
    <div role="status" style={{ marginTop: 12, color: '#1f6feb', fontSize: 13 }}>
      Analyzing...
    </div>
  )
}
