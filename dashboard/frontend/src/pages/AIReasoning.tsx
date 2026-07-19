import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getIncidents, getReasoning, runLiveAiPipeline, type Incident, type ReasoningOutput } from '../api/client'
import DeceptionCard from '../components/DeceptionCard'
import HypothesisCard from '../components/HypothesisCard'
import PredictionFlow from '../components/PredictionFlow'
import ResponsePlan from '../components/ResponsePlan'
import StatusBadge from '../components/StatusBadge'

export default function AIReasoning() {
  const { id = 'INC-GRAPH-001' } = useParams()
  const [reasoning, setReasoning] = useState<ReasoningOutput | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [runMessage, setRunMessage] = useState<string | null>(null)

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
      setRunMessage('Live AI pipeline completed. Agent stages were persisted to the audit ledger when backend execution succeeded.')
    } catch (error) {
      setRunMessage(error instanceof Error ? error.message : 'Live AI pipeline failed.')
    } finally {
      setIsRunning(false)
    }
  }

  if (!reasoning || !incident) return null
  const threatColor = incident.unified_threat_score >= 0.75 ? 'var(--danger)' : incident.unified_threat_score >= 0.5 ? 'var(--warning)' : 'var(--safe)'
  const sorted = [...reasoning.hypotheses].sort((a, b) => b.confidence - a.confidence)

  return (
    <div className="reasoning-grid">
      <div className="reasoning-header">
        <div>
          <p className="eyebrow">AI Reasoning Pipeline</p>
          <h1 className="mono">{reasoning.incident_id}</h1>
          <p className="subtle">{new Date(incident.timestamp).toLocaleString()} | {incident.attack_class}</p>
          <div className="action-row" style={{ marginTop: 12 }}>
            <button className="btn primary" onClick={runAgents} disabled={isRunning}>{isRunning ? 'Running Agents...' : 'Run Live AI Pipeline'}</button>
            {'source' in reasoning && <span className="badge neutral">SOURCE: {String(reasoning.source).toUpperCase()}</span>}
          </div>
          {runMessage && <div className="warning-card">{runMessage}</div>}
        </div>
        <div className="card tight">
          <div className="action-row"><StatusBadge status={incident.status} /><span className="mono score high">{incident.unified_threat_score.toFixed(2)}</span></div>
          <div className="threat-bar"><div className="threat-fill" style={{ width: `${incident.unified_threat_score * 100}%`, background: threatColor }} /></div>
        </div>
      </div>
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
      <DeceptionCard strategy={reasoning.deception_strategy} />
      <ResponsePlan plan={reasoning.response_plan} incidentId={id} />
    </div>
  )
}
