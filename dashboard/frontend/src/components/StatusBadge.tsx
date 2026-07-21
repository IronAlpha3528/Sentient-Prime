export default function StatusBadge({ status }: { status: string }) {
  const key = status.toUpperCase()
  const tone = key.includes('ACTIVE') || key.includes('ESCALATED') || key.includes('TRIGGERED') || key.includes('BLOCKED')
    ? key.includes('ACTIVE') || key.includes('TRIGGERED') ? 'warning' : 'danger'
    : key.includes('RESOLVED') || key.includes('SOAR') || key.includes('VERIFIED') || key.includes('PASSED') || key.includes('COMPLETE') ? 'safe'
    : key.includes('HYPOTHESIS') || key.includes('AI') || key.includes('RUNNING') ? 'info'
    : 'neutral'

  return (
    <span className={`badge ${tone}`}>
      <span className="status-dot" style={{ 
        width: 6, 
        height: 6, 
        background: tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : tone === 'safe' ? 'var(--safe)' : tone === 'info' ? 'var(--info)' : 'var(--text-muted)' 
      }} />
      <span>{status}</span>
    </span>
  )
}
