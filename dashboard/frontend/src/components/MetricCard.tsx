export default function MetricCard({ label, value, subtitle, tone = 'neutral' }: { label: string; value: string; subtitle: string; tone?: 'danger' | 'warning' | 'safe' | 'neutral' }) {
  const color = tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : tone === 'safe' ? 'var(--safe)' : 'var(--text)'
  return (
    <section className="card metric-card">
      <span className="metric-label">{label}</span>
      <strong className="metric-value" style={{ color }}>{value}</strong>
      <span className="metric-subtitle">{subtitle}</span>
    </section>
  )
}
