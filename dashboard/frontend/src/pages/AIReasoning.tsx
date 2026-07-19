import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  getIncidents,
  getReasoning,
  runLiveAiPipeline,
  streamAiPipeline,
  type Incident,
  type PipelineStageEvent,
  type ReasoningOutput,
} from '../api/client'
import DeceptionCard from '../components/DeceptionCard'
import HypothesisCard from '../components/HypothesisCard'
import PredictionFlow from '../components/PredictionFlow'
import ResponsePlan from '../components/ResponsePlan'
import StatusBadge from '../components/StatusBadge'

// ─── Streaming stage tracker ──────────────────────────────────────────────────

const STAGES = [
  { num: 1, name: 'Analysis Agent', desc: 'Correlating evidence, generating hypotheses, predicting attack path' },
  { num: 2, name: 'Critique Agent', desc: 'Validating hypotheses for logical leaps and hallucinations' },
  { num: 3, name: 'Action Agent', desc: 'Proposing parameterized containment and deception actions' },
]

type StageStatus = 'waiting' | 'running' | 'done' | 'error'

function StreamingPanel({ stages }: { stages: { status: StageStatus; name: string; desc: string; detail?: string }[] }) {
  return (
    <div style={{ display: 'grid', gap: 12, marginBottom: 20 }}>
      {stages.map((s, i) => {
        const color = s.status === 'done' ? 'var(--safe)' : s.status === 'running' ? 'var(--primary)' : s.status === 'error' ? 'var(--danger)' : 'var(--muted)'
        const icon = s.status === 'done' ? '✓' : s.status === 'running' ? '⟳' : s.status === 'error' ? '✕' : '○'
        return (
          <div key={i} className="card tight" style={{ borderColor: s.status === 'running' ? 'var(--primary)' : s.status === 'done' ? 'rgba(34,197,94,0.28)' : 'var(--border)', transition: 'border-color 400ms' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className="mono" style={{ color, fontSize: 18, width: 20, display: 'inline-block', animation: s.status === 'running' ? 'pulse-opacity 1s ease-in-out infinite' : undefined }}>{icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="eyebrow" style={{ color, margin: 0 }}>Stage {i + 1}</span>
                  <strong>{s.name}</strong>
                </div>
                <p className="subtle" style={{ margin: '2px 0 0', fontSize: 12 }}>{s.status === 'running' ? s.desc : (s.detail || s.desc)}</p>
              </div>
              {s.status === 'done' && <span className="badge safe">COMPLETE</span>}
              {s.status === 'running' && <span className="badge info pulse">RUNNING</span>}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function AIReasoning() {
  const { id = 'INC-GRAPH-001' } = useParams()
  const [reasoning, setReasoning] = useState<ReasoningOutput | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [runMessage, setRunMessage] = useState<string | null>(null)
  const [isStreaming, setIsStreaming] = useState(false)
  const [stageStatuses, setStageStatuses] = useState<StageStatus[]>(['waiting', 'waiting', 'waiting'])
  const cancelStreamRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    getReasoning(id).then(setReasoning)
    getIncidents().then((items) => setIncident(items.find((item) => item.incident_id === id) ?? items[0]))
  }, [id])

  // ── Classic (batch) run ────────────────────────────────────────────────────
  const runAgents = async () => {
    setIsRunning(true)
    setRunMessage(null)
    try {
      const result = await runLiveAiPipeline(id)
      setReasoning(result)
      setRunMessage('Live AI pipeline completed. Agent stages were persisted to the audit ledger.')
    } catch (error) {
      setRunMessage(error instanceof Error ? error.message : 'Live AI pipeline failed.')
    } finally {
      setIsRunning(false)
    }
  }

  // ── Streaming run ──────────────────────────────────────────────────────────
  const runStream = () => {
    if (isStreaming) {
      cancelStreamRef.current?.()
      setIsStreaming(false)
      setStageStatuses(['waiting', 'waiting', 'waiting'])
      return
    }
    setIsStreaming(true)
    setRunMessage(null)
    setStageStatuses(['waiting', 'waiting', 'waiting'])

    const cancel = streamAiPipeline(
      id,
      (event: PipelineStageEvent) => {
        if (event.type === 'stage_start' && event.stage) {
          setStageStatuses((prev) => {
            const next = [...prev]
            next[event.stage! - 1] = 'running'
            return next
          })
        }
        if (event.type === 'stage_complete' && event.stage) {
          setStageStatuses((prev) => {
            const next = [...prev]
            next[event.stage! - 1] = 'done'
            return next
          })
        }
        if (event.type === 'error') {
          setStageStatuses(['error', 'error', 'error'])
          setRunMessage(`Pipeline error: ${event.message}`)
          setIsStreaming(false)
        }
      },
      (result) => {
        setReasoning(result)
        setStageStatuses(['done', 'done', 'done'])
        setRunMessage('Streaming pipeline complete. All 3 agent stages logged to the audit ledger.')
        setIsStreaming(false)
      },
      (errMsg) => {
        setRunMessage(`Stream error: ${errMsg}`)
        setStageStatuses(['error', 'error', 'error'])
        setIsStreaming(false)
      },
    )
    cancelStreamRef.current = cancel
  }

  if (!reasoning || !incident) return null
  const threatColor = incident.unified_threat_score >= 0.75 ? 'var(--danger)' : incident.unified_threat_score >= 0.5 ? 'var(--warning)' : 'var(--safe)'
  const sorted = [...reasoning.hypotheses].sort((a, b) => b.confidence - a.confidence)
  const streamingStages = STAGES.map((s, i) => ({ ...s, status: stageStatuses[i] }))

  return (
    <div className="reasoning-grid">
      <div className="reasoning-header">
        <div>
          <p className="eyebrow">AI Reasoning Pipeline</p>
          <h1 className="mono">{reasoning.incident_id}</h1>
          <p className="subtle">{new Date(incident.timestamp).toLocaleString()} | {incident.attack_class}</p>
          <div className="action-row" style={{ marginTop: 12, gap: 10 }}>
            <button className="btn primary" onClick={runStream} disabled={isRunning}>
              {isStreaming ? '■ Stop Stream' : '▶ Stream Live Pipeline'}
            </button>
            <button className="btn secondary" onClick={runAgents} disabled={isRunning || isStreaming}>
              {isRunning ? 'Running...' : 'Run (Batch)'}
            </button>
            {'source' in reasoning && <span className="badge neutral">SOURCE: {String(reasoning.source).toUpperCase()}</span>}
          </div>
          {runMessage && <div className="warning-card" style={{ marginTop: 12 }}>{runMessage}</div>}
        </div>
        <div className="card tight">
          <div className="action-row"><StatusBadge status={incident.status} /><span className="mono score high">{incident.unified_threat_score.toFixed(2)}</span></div>
          <div className="threat-bar"><div className="threat-fill" style={{ width: `${incident.unified_threat_score * 100}%`, background: threatColor }} /></div>
        </div>
      </div>

      {/* Live streaming progress panel */}
      {(isStreaming || stageStatuses.some((s) => s !== 'waiting')) && (
        <section className="card" style={{ borderColor: 'rgba(56,189,248,0.22)', background: 'rgba(7,12,24,0.98)' }}>
          <h2 style={{ marginBottom: 16 }}>⚡ Live Agent Execution</h2>
          <StreamingPanel stages={streamingStages} />
        </section>
      )}

      <section className="card">
        <h2>Incident Story</h2>
        <p className="story">{reasoning.story.narrative}</p>
        <div className="domain-row">{reasoning.story.domains_involved.map((domain) => <span className="badge info" key={domain}>{domain}</span>)}</div>
      </section>
      <section className="grid">
        <h2 style={{ marginBottom: 0 }}>Hypothesis Ladder</h2>
        {sorted.map((hypothesis) => <HypothesisCard hypothesis={hypothesis} key={hypothesis.title} />)}
      </section>
      <PredictionFlow prediction={reasoning.prediction} />
      <DeceptionCard strategy={reasoning.deception_strategy} incidentId={id} />
      <ResponsePlan plan={reasoning.response_plan} incidentId={id} />
    </div>
  )
}
