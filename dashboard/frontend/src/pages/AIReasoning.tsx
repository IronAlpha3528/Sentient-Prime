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

const STAGES = [
  { num: 1, name: 'Analysis Agent', desc: 'Correlating cross-domain telemetry, generating hypotheses, and predicting lateral movement' },
  { num: 2, name: 'Critique Agent', desc: 'Validating hypotheses for logical leaps, hallucinations, and false positives' },
  { num: 3, name: 'Action Agent', desc: 'Proposing policy-bound containment actions and honeytoken deception strategy' },
]

type StageStatus = 'waiting' | 'running' | 'done' | 'error'

function StreamingPanel({ stages }: { stages: { status: StageStatus; name: string; desc: string; detail?: string }[] }) {
  return (
    <div style={{ display: 'grid', gap: 12, marginBottom: 20 }}>
      {stages.map((s, i) => {
        const color = s.status === 'done' ? 'var(--safe)' : s.status === 'running' ? 'var(--primary)' : s.status === 'error' ? 'var(--danger)' : 'var(--text-subtle)'
        const icon = s.status === 'done' ? '✓' : s.status === 'running' ? '⟳' : s.status === 'error' ? '✕' : '○'
        return (
          <div 
            key={i} 
            className="card tight" 
            style={{ 
              borderColor: s.status === 'running' ? 'var(--primary)' : s.status === 'done' ? 'rgba(52,211,153,0.3)' : 'var(--border)', 
              background: s.status === 'running' ? 'rgba(56,189,248,0.06)' : undefined,
              transition: 'all 300ms ease' 
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <span className="mono" style={{ color, fontSize: 18, width: 22, textAlign: 'center', animation: s.status === 'running' ? 'pulse-dot 1s infinite' : undefined }}>
                {icon}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className="eyebrow" style={{ color, margin: 0 }}>STAGE {i + 1}</span>
                  <strong style={{ fontSize: 15 }}>{s.name}</strong>
                </div>
                <p className="subtle" style={{ margin: '4px 0 0', fontSize: 13 }}>{s.status === 'running' ? s.desc : (s.detail || s.desc)}</p>
              </div>
              {s.status === 'done' && <span className="badge safe">COMPLETE</span>}
              {s.status === 'running' && <span className="badge info pulse">EXECUTING</span>}
              {s.status === 'waiting' && <span className="badge neutral">QUEUED</span>}
            </div>
          </div>
        )
      })}
    </div>
  )
}

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

  const runAgents = async () => {
    setIsRunning(true)
    setRunMessage(null)
    try {
      const result = await runLiveAiPipeline(id)
      setReasoning(result)
      setRunMessage('✓ Live AI multi-agent reasoning complete. Agent execution traces written to tamper-evident audit ledger.')
    } catch (error) {
      setRunMessage(error instanceof Error ? error.message : 'Live AI pipeline execution encountered an error.')
    } finally {
      setIsRunning(false)
    }
  }

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
        setRunMessage('✓ Streaming pipeline complete. All 3 agent stages logged to audit ledger.')
        setIsStreaming(false)
      },
      (errMsg) => {
        setRunMessage(`Stream connection error: ${errMsg}`)
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
        <div className="card accent-primary" style={{ padding: 24 }}>
          <p className="eyebrow">AUTONOMOUS MULTI-AGENT REASONING</p>
          <h1 className="mono" style={{ color: 'var(--primary)' }}>{reasoning.incident_id}</h1>
          <p className="subtle" style={{ margin: '4px 0 16px 0' }}>
            {new Date(incident.timestamp).toLocaleString()} &nbsp;|&nbsp; 
            Attack Class: <strong style={{ color: 'var(--text-main)' }}>{incident.attack_class}</strong>
          </p>
          
          <div className="action-row">
            <button className="btn primary" onClick={runStream} disabled={isRunning}>
              {isStreaming ? '■ Stop Stream' : '▶ Execute Live AI Pipeline'}
            </button>
            <button className="btn secondary" onClick={runAgents} disabled={isRunning || isStreaming}>
              {isRunning ? 'Running...' : 'Run Pipeline (Batch)'}
            </button>
            {'source' in reasoning && (
              <span className="badge neutral mono">SOURCE: {String(reasoning.source).toUpperCase()}</span>
            )}
          </div>

          {runMessage && (
            <div className="warning-card" style={{ borderColor: 'rgba(52,211,153,0.3)', background: 'rgba(52,211,153,0.08)', color: 'var(--safe)', marginTop: 16 }}>
              {runMessage}
            </div>
          )}
        </div>

        <div className="card tight accent-danger" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <StatusBadge status={incident.status} />
            <span className="mono score high" style={{ fontSize: 24 }}>
              {incident.unified_threat_score.toFixed(2)}
            </span>
          </div>

          <div style={{ fontSize: 11, color: 'var(--text-subtle)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>
            CORRELATED THREAT SCORE
          </div>

          <div className="progress" style={{ margin: 0, height: 8 }}>
            <div className="progress-fill" style={{ width: `${incident.unified_threat_score * 100}%`, background: threatColor }} />
          </div>
        </div>
      </div>

      {/* Streaming agent execution status panel */}
      {(isStreaming || stageStatuses.some((s) => s !== 'waiting')) && (
        <section className="card glow-primary">
          <h2>⚡ Live Agent Execution Pipeline</h2>
          <StreamingPanel stages={streamingStages} />
        </section>
      )}

      <section className="card">
        <h2>Correlated Incident Narrative</h2>
        <p className="story">{reasoning.story.narrative}</p>
        <div className="domain-row">
          <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>DOMAINS INVOLVED:</span>
          {reasoning.story.domains_involved.map((domain) => (
            <span className="badge info" key={domain}>{domain}</span>
          ))}
        </div>
      </section>

      <section className="grid">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2>Ranked Hypothesis Ladder</h2>
          <span className="subtle mono" style={{ fontSize: 12 }}>{sorted.length} Evaluated Hypotheses</span>
        </div>
        {sorted.map((hypothesis) => (
          <HypothesisCard hypothesis={hypothesis} key={hypothesis.title} />
        ))}
      </section>

      <PredictionFlow prediction={reasoning.prediction} />
      <DeceptionCard strategy={reasoning.deception_strategy} incidentId={id} />
      <ResponsePlan plan={reasoning.response_plan} incidentId={id} />
    </div>
  )
}
