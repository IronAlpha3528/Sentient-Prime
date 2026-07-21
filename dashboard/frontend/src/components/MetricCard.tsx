interface MetricCardProps {
  label: string
  value: string
  subtitle: string
  tone?: 'danger' | 'warning' | 'safe' | 'neutral' | 'primary'
  icon?: string
}

export default function MetricCard({ label, value, subtitle, tone = 'neutral' }: MetricCardProps) {
  const color = tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : tone === 'safe' ? 'var(--safe)' : 'var(--primary)'
  const accentClass = `accent-${tone}`

  const getIcon = () => {
    if (label.toLowerCase().includes('threat')) {
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      )
    }
    if (label.toLowerCase().includes('mttd')) {
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      )
    }
    if (label.toLowerCase().includes('mttr')) {
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
        </svg>
      )
    }
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
        <polyline points="22 4 12 14.01 9 11.01" />
      </svg>
    )
  }

  return (
    <section className={`card metric-card ${accentClass}`}>
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <div className="metric-icon-wrap">
          {getIcon()}
        </div>
      </div>
      <div>
        <div className="metric-value" style={{ color }}>{value}</div>
        <div className="metric-subtitle">{subtitle}</div>
      </div>
    </section>
  )
}
