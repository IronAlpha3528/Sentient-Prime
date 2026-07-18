export default function StatusBadge({ status }: { status: string }) {
  const key = status.toUpperCase()
  const tone = key.includes('ACTIVE') || key.includes('ESCALATED') || key.includes('TRIGGERED')
    ? key.includes('ACTIVE') ? 'warning' : 'danger'
    : key.includes('RESOLVED') || key.includes('SOAR') || key.includes('VERIFIED') ? 'safe'
    : key.includes('HYPOTHESIS') || key.includes('AI') ? 'info'
    : 'neutral'
  return <span className={`badge ${tone}`}>{status}</span>
}
