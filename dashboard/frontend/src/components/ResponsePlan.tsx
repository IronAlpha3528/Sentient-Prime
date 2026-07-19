import { useState } from 'react'
import { approveIncident, rejectIncident } from '../api/client'
import type { ReasoningOutput } from '../api/client'
import StatusBadge from './StatusBadge'

export default function ResponsePlan({ plan, incidentId }: { plan: ReasoningOutput['response_plan']; incidentId: string }) {
  const [modal, setModal] = useState<'approve' | 'reject' | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const handleConfirm = async () => {
    if (!modal) return
    setIsSubmitting(true)
    try {
      if (modal === 'approve') {
        await approveIncident(incidentId)
        setActionMessage('Containment approved. SOAR playbook dispatched.')
      } else {
        await rejectIncident(incidentId)
        setActionMessage('Action rejected. Incident remains in monitoring queue.')
      }
      setModal(null)
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : 'Action failed.')
      setModal(null)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <section className="card">
      <h2>Response Plan & Policy Gate</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Action</th><th>Target</th><th>Containment Score</th><th>Business Impact</th><th>Composite Score</th></tr></thead>
          <tbody>
            {plan.recommended_actions.map((action) => (
              <tr key={`${action.action}-${action.target}`}>
                <td className="mono">{action.action}</td>
                <td>{action.target}</td>
                <td className="score high">{action.containment_score.toFixed(2)}</td>
                <td className="score mid">{action.business_impact.toFixed(2)}</td>
                <td className="score">{action.composite_score.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="action-row" style={{ marginTop: 16 }}>
        <StatusBadge status={plan.routing_decision} />
        <StatusBadge status={plan.policy_gate_passed ? 'POLICY_GATE_PASSED' : 'POLICY_GATE_BLOCKED'} />
      </div>
      {plan.dry_run_warnings.map((warning) => <div className="warning-card" key={warning}>{warning}</div>)}
      {actionMessage && <div className="warning-card" style={{ marginTop: 12 }}>{actionMessage}</div>}
      {plan.routing_decision === 'HUMAN_ESCALATION' && (
        <div className="action-row" style={{ marginTop: 16 }}>
          <button className="btn primary" onClick={() => setModal('approve')}>Approve Containment</button>
          <button className="btn secondary" onClick={() => setModal('reject')}>Reject / Monitor Only</button>
        </div>
      )}
      {modal && (
        <div className="modal-backdrop">
          <div className="modal">
            <h2>{modal === 'approve' ? 'Approve Containment' : 'Reject / Monitor Only'}</h2>
            <p className="subtle">Confirm analyst decision for this incident response route.</p>
            <div className="action-row" style={{ justifyContent: 'flex-end' }}>
              <button className="btn secondary" onClick={() => setModal(null)} disabled={isSubmitting}>Cancel</button>
              <button className="btn primary" onClick={handleConfirm} disabled={isSubmitting}>
                {isSubmitting ? 'Submitting...' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
