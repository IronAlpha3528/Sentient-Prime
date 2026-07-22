import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getAuditLog, getIncidents, getMetrics, getTopology, type AuditEntry, type Incident, type Topology } from '../api/client'
import AuditFeed from '../components/AuditFeed'
import IncidentTable from '../components/IncidentTable'
import MetricCard from '../components/MetricCard'

import ThreatGauge from '../components/ThreatGauge'
import ThreatGraph from '../components/ThreatGraph'

/* ─── Custom X-axis tick with detector icons ─────────────────────────────── */
const DETECTOR_ICONS: Record<string, string> = {
  Network: '🌐',
  Identity: '👤',
  Endpoint: '💻',
  OT: '🏭',
}

function CustomTick(props: any) {
  const { x, y, payload } = props
  const icon = DETECTOR_ICONS[payload.value] || '◆'
  return (
    <g transform={`translate(${x},${y})`}>
      <text x={0} y={0} dy={18} textAnchor="middle" fill="#94a3b8" fontSize={15}>
        {icon}
      </text>
      <text x={0} y={0} dy={34} textAnchor="middle" fill="#64748b" fontSize={11} fontFamily="var(--font-mono)">
        {payload.value}
      </text>
    </g>
  )
}

/* ─── Custom value label renderer ────────────────────────────────────────── */
function renderValueLabel(props: any) {
  const { x, y, width, value } = props
  if (value == null) return null
  const pct = `${Math.round(value * 100)}%`
  return (
    <text
      x={x + width / 2}
      y={y - 8}
      textAnchor="middle"
      fill="#e2e8f0"
      fontSize={11}
      fontFamily="var(--font-mono)"
      fontWeight={600}
    >
      {pct}
    </text>
  )
}

/* ─── Custom tooltip ─────────────────────────────────────────────────────── */
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  const icon = DETECTOR_ICONS[label] || ''
  return (
    <div style={{
      background: 'rgba(9, 14, 28, 0.96)',
      border: '1px solid rgba(0, 240, 255, 0.25)',
      borderRadius: 10,
      padding: '10px 16px',
      fontFamily: 'var(--font-mono)',
      fontSize: 12,
      color: '#f8fafc',
      backdropFilter: 'blur(12px)',
      minWidth: 160,
    }}>
      <div style={{ fontWeight: 700, marginBottom: 8, fontSize: 13, letterSpacing: '0.05em' }}>
        {icon} {label}
      </div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ display: 'flex', justifyContent: 'space-between', gap: 20, padding: '2px 0' }}>
          <span style={{ color: p.dataKey === 'precision' ? '#00f0ff' : '#00ff9d', textTransform: 'capitalize' }}>
            {p.dataKey}
          </span>
          <span style={{ fontWeight: 700, color: p.dataKey === 'precision' ? '#00f0ff' : '#00ff9d' }}>
            {Math.round(p.value * 100)}%
          </span>
        </div>
      ))}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Overview Page                                                              */
/* ═══════════════════════════════════════════════════════════════════════════ */
export default function Overview() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [topology, setTopology] = useState<Topology | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [metrics, setMetrics] = useState<any>(null)
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())

  useEffect(() => {
    const load = () => {
      Promise.all([getIncidents(), getTopology(), getAuditLog(), getMetrics()]).then(([inc, top, aud, met]) => {
        setIncidents(inc)
        setTopology(top)
        setAudit(aud)
        setMetrics(met)
        setLastUpdated(new Date())
      }).catch(() => {})
    }
    load()
    const id = setInterval(load, 10_000)
    return () => clearInterval(id)
  }, [])

  const topScore = Math.max(...incidents.map((incident) => incident.unified_threat_score || 0), 0)
  const chartData = metrics?.detector_scores 
    ? Object.entries(metrics.detector_scores).map(([name, data]: any) => {
        const displayName = name === 'ot' ? 'OT' : name.charAt(0).toUpperCase() + name.slice(1)
        return { name: displayName, precision: data?.precision ?? 0, recall: data?.recall ?? 0 }
      }) 
    : []

  return (
    <div className="overview-layout">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <p className="eyebrow">
            COMMAND CONSOLE
            <span className="badge danger pulse" style={{ marginLeft: 10, padding: '2px 8px' }}>DEFCON 1</span>
          </p>
          <h1>Cyber Resilience Command Surface</h1>
          <p className="subtle">
            Autonomous multi-agent detection, honeytoken deception, orchestration, and tamper-evident auditability.
            <span style={{ marginLeft: 12, fontSize: 11, color: 'var(--cyber-cyan)' }} className="mono">
              [SYNC: {lastUpdated.toLocaleTimeString()}]
            </span>
          </p>
        </div>
      </div>

      {/* Top Hero Section: Threat Gauge + Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 24, alignItems: 'stretch' }}>
        <div className="card glow-primary" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <ThreatGauge score={topScore} size={150} label="TOP THREAT" />
        </div>

        <div className="grid metrics-grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
          <MetricCard label="MTTD" value={`${metrics?.mttd_minutes ?? 0} min`} subtitle="Mean Time to Detect" tone="warning" />
          <MetricCard label="MTTR" value={`${metrics?.mttr_minutes ?? 0} min`} subtitle="Mean Time to Contain" tone="primary" />
          <MetricCard label="Automation Rate" value={`${Math.round((metrics?.automation_rate ?? 0) * 100)}%`} subtitle="SOAR Auto-Executed" tone="safe" />
        </div>
      </div>

      {/* Threat Topology Visualizer */}
      {topology && <ThreatGraph topology={topology} height={500} />}

      {/* Incidents Table + Live Audit Log Feed */}
      <div className="grid bottom-grid">
        <section className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h2>Correlated Incident Queue</h2>
            <span className="mono subtle" style={{ fontSize: 11, color: 'var(--cyber-cyan)' }}>LIVE CORRELATION</span>
          </div>
          <IncidentTable incidents={incidents.slice(0, 5)} compact />
        </section>

        <section className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h2>Tamper-Evident Audit Feed</h2>
            <span className="badge safe">LEDGER VERIFIED</span>
          </div>
          <AuditFeed entries={audit} />
        </section>
      </div>

      {/* ─── AI Detector Precision & Recall Health ─────────────────────────── */}
      <section className="card detector-health-card">
        <div className="detector-health-header">
          <div>
            <h2>AI Detector Precision & Recall Health</h2>
            <p className="subtle">Cross-detector performance across network, endpoint, OT, and identity models.</p>
          </div>
          <div className="detector-legend">
            <span className="legend-item">
              <span className="legend-dot" style={{ background: '#00f0ff' }} />
              <span style={{ color: '#00f0ff' }}>Precision</span>
            </span>
            <span className="legend-item">
              <span className="legend-dot" style={{ background: '#00ff9d' }} />
              <span style={{ color: '#00ff9d' }}>Recall</span>
            </span>
          </div>
        </div>

        <div className="health-chart">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 30, right: 30, left: 10, bottom: 40 }} barGap={8} barCategoryGap="25%">
              {/* SVG gradient definitions */}
              <defs>
                <linearGradient id="gradPrecision" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.9} />
                  <stop offset="100%" stopColor="#00f0ff" stopOpacity={0.15} />
                </linearGradient>
                <linearGradient id="gradRecall" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00ff9d" stopOpacity={0.9} />
                  <stop offset="100%" stopColor="#00ff9d" stopOpacity={0.15} />
                </linearGradient>
                <filter id="glowCyan">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="glowGreen">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />

              <XAxis
                dataKey="name"
                stroke="transparent"
                tickLine={false}
                axisLine={false}
                tick={<CustomTick />}
                height={50}
              />

              <YAxis
                stroke="#334155"
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
                ticks={[0, 0.25, 0.5, 0.75, 1]}
                tickFormatter={(v: number) => `${Math.round(v * 100)}%`}
                style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}
                width={45}
              />

              <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(0,240,255,0.04)' }} />

              {/* Precision bars — sleek rounded lollipop style */}
              <Bar
                dataKey="precision"
                fill="url(#gradPrecision)"
                barSize={12}
                radius={[6, 6, 0, 0]}
                isAnimationActive={true}
                animationDuration={800}
                animationEasing="ease-out"
                
              >
                <LabelList dataKey="precision" content={renderValueLabel} />
              </Bar>

              {/* Recall bars */}
              <Bar
                dataKey="recall"
                fill="url(#gradRecall)"
                barSize={12}
                radius={[6, 6, 0, 0]}
                isAnimationActive={true}
                animationDuration={800}
                animationEasing="ease-out"
                
              >
                <LabelList dataKey="recall" content={renderValueLabel} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  )
}
