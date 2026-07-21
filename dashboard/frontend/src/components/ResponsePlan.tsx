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
        setActionMessage('✓ Containment approved. SOAR playbook dispatched.')
      } else {
        await rejectIncident(incidentId)
        setActionMessage('✓ Action rejected. Incident remains in monitoring queue.')
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
    <section className="card accent-safe">
      <h2>Recommended Response Plan & Policy Gate</h2>

      <div className="table-wrap" style={{ marginBottom: 16 }}>
        <table>
          <thead>
            <tr>
              <th>RECOMMENDED ACTION</th>
              <th>TARGET ASSET</th>
              <th>CONTAINMENT SCORE</th>
              <th>BUSINESS IMPACT</th>
              <th>COMPOSITE SCORE</th>
            </tr>
          </thead>
          <tbody>
            {plan.recommended_actions.map((action, idx) => (
              <tr key={`${action.action}-${idx}`}>
                <td className="mono" style={{ fontWeight: 600, color: 'var(--primary)' }}>{action.action}</td>
                <td>{action.target}</td>
                <td className="score high">{action.containment_score.toFixed(2)}</td>
                <td className="score mid">{action.business_impact.toFixed(2)}</td>
                <td className="score" style={{ color: '#ffffff' }}>{action.composite_score.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="action-row" style={{ marginBottom: 14 }}>
        <StatusBadge status={plan.routing_decision} />
        <StatusBadge status={plan.policy_gate_passed ? 'POLICY_GATE_PASSED' : 'POLICY_GATE_BLOCKED'} />
      </div>

      {plan.dry_run_warnings.map((warning, i) => (
        <div className="warning-card" key={i}>
          ⚠️ <strong>Dry Run Warning:</strong> {warning}
        </div>
      ))}

      {actionMessage && (
        <div className="warning-card" style={{ borderColor: 'rgba(52,211,153,0.3)', background: 'rgba(52,211,153,0.08)', color: 'var(--safe)' }}>
          {actionMessage}
        </div>
      )}

      {plan.routing_decision === 'HUMAN_ESCALATION' && (
        <div className="action-row" style={{ marginTop: 20 }}>
          <button className="btn primary" onClick={() => setModal('approve')} style={{ flex: 1 }}>
            ✓ Approve Containment Playbook
          </button>
          <button className="btn secondary" onClick={() => setModal('reject')} style={{ flex: 1, color: 'var(--danger)', borderColor: 'rgba(244,63,94,0.4)' }}>
            ✕ Reject / Monitor Only
          </button>
        </div>
      )}

      {modal && (
        <div className="modal-backdrop">
          <div className="modal">
            <h2>{modal === 'approve' ? 'Approve Containment' : 'Reject Action'}</h2>
            <p className="subtle" style={{ marginBottom: 20 }}>
              {modal === 'approve' 
                ? 'Confirming will trigger automatic SOAR playbook containment for this incident target.' 
                : 'Rejecting will keep the target uncontained under passive SOC monitoring.'}
            </p>
            <div className="action-row" style={{ justifyContent: 'flex-end', gap: 12 }}>
              <button className="btn secondary" onClick={() => setModal(null)} disabled={isSubmitting}>
                Cancel
              </button>
              <button className={modal === 'approve' ? 'btn primary' : 'btn danger'} onClick={handleConfirm} disabled={isSubmitting}>
                {isSubmitting ? 'Dispatching...' : 'Confirm Analyst Action'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
