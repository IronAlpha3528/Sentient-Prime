interface ThreatGaugeProps {
  score: number // 0.00 to 1.00
  size?: number
  label?: string
}

export default function ThreatGauge({ score, size = 160, label = 'THREAT LEVEL' }: ThreatGaugeProps) {
  const normalized = Math.max(0, Math.min(1, score))
  const radius = (size - 24) / 2
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - normalized * circumference * 0.75 // 270 deg arc

  const color = normalized >= 0.75 
    ? 'var(--crimson-alert)' 
    : normalized >= 0.5 
    ? 'var(--cyber-gold)' 
    : 'var(--matrix-green)'

  const statusText = normalized >= 0.75 
    ? 'CRITICAL IMMINENT' 
    : normalized >= 0.5 
    ? 'ELEVATED RISK' 
    : 'OPTIMAL DEFENSE'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(135deg)', filter: `drop-shadow(0 0 12px ${color})` }}>
        {/* Background Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * 0.25}
          strokeLinecap="round"
        />
        {/* Active Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 800ms cubic-bezier(0.4, 0, 0.2, 1), stroke 300ms ease' }}
        />
      </svg>

      {/* Inner Score Text */}
      <div style={{ position: 'absolute', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <span className="mono" style={{ fontFamily: 'var(--font-hud)', fontSize: size > 140 ? 32 : 24, fontWeight: 900, color, lineHeight: 1, textShadow: `0 0 12px ${color}` }}>
          {normalized.toFixed(2)}
        </span>
        <span style={{ fontFamily: 'var(--font-hud)', fontSize: size > 140 ? 9 : 8, color: 'var(--text-subtle)', marginTop: 4, letterSpacing: '1px' }}>
          {label}
        </span>
        <span className="badge" style={{ marginTop: 6, fontSize: 9, padding: '2px 8px', background: `${color}15`, color, borderColor: `${color}40` }}>
          {statusText}
        </span>
      </div>
    </div>
  )
}
