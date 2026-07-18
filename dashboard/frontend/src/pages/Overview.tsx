import { useEffect, useState } from 'react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getAuditLog, getIncidents, getMetrics, getTopology, type AuditEntry, type Incident, type Topology } from '../api/client'
import AuditFeed from '../components/AuditFeed'
import IncidentTable from '../components/IncidentTable'
import MetricCard from '../components/MetricCard'
import ThreatGraph from '../components/ThreatGraph'

export default function Overview() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [topology, setTopology] = useState<Topology | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [metrics, setMetrics] = useState<any>(null)

  useEffect(() => {
    getIncidents().then(setIncidents)
    getTopology().then(setTopology)
    getAuditLog().then(setAudit)
    getMetrics().then(setMetrics)
  }, [])

  const topScore = Math.max(...incidents.map((incident) => incident.unified_threat_score), 0)
  const chartData = metrics ? Object.entries(metrics.detector_scores).map(([name, data]: any) => ({ name, precision: data.precision, recall: data.recall })) : []

  return (
    <div className="grid overview-layout">
      <div className="page-header">
        <div><p className="eyebrow">Command Center</p><h1>Sentient-Prime Cyber Resilience</h1><p className="subtle">AI-led detection, deception, orchestration, and auditability for CNI operations.</p></div>
      </div>
      <div className="grid metrics-grid">
        <MetricCard label="Threat Score" value={topScore.toFixed(2)} subtitle="Highest Active" tone="danger" />
        <MetricCard label="MTTD" value={`${metrics?.mttd_minutes ?? 0} min`} subtitle="Mean Time to Detect" />
        <MetricCard label="MTTR" value={`${metrics?.mttr_minutes ?? 0} min`} subtitle="Mean Time to Respond" />
        <MetricCard label="Automation" value={`${Math.round((metrics?.automation_rate ?? 0) * 100)}%`} subtitle="Auto-Contained" tone="safe" />
      </div>
      {topology && <ThreatGraph topology={topology} height={520} />}
      <div className="grid bottom-grid">
        <section className="card"><h2>Recent Incidents</h2><IncidentTable incidents={incidents.slice(0, 5)} compact /></section>
        <section className="card"><h2>Live Audit Feed</h2><AuditFeed entries={audit} /></section>
      </div>
      <section className="card">
        <h2>Detector Health</h2>
        <div className="health-chart">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <XAxis dataKey="name" stroke="#71717a" tickLine={false} axisLine={false} />
              <YAxis stroke="#71717a" tickLine={false} axisLine={false} domain={[0, 1]} />
              <Tooltip contentStyle={{ background: '#0b1020', border: '1px solid rgba(148,163,184,0.24)', color: '#e5e7eb' }} />
              <Bar dataKey="precision" fill="#6366f1" radius={[6, 6, 0, 0]} />
              <Bar dataKey="recall" fill="#22c55e" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  )
}
