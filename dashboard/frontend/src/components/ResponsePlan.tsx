import { useState } from 'react'
import type { ReasoningOutput } from '../api/client'
import StatusBadge from './StatusBadge'

export default function ResponsePlan({ plan }: { plan: ReasoningOutput['response_plan'] }) {
  const [modal, setModal] = useState<string | null>(null)
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
      {plan.routing_decision === 'HUMAN_ESCALATION' && (
        <div className="action-row" style={{ marginTop: 16 }}>
          <button className="btn primary" onClick={() => setModal('Approve Containment')}>Approve Containment</button>
          <button className="btn secondary" onClick={() => setModal('Reject / Monitor Only')}>Reject / Monitor Only</button>
        </div>
      )}
      {modal && (
        <div className="modal-backdrop">
          <div className="modal">
            <h2>{modal}</h2>
            <p className="subtle">Confirm analyst decision for this incident response route.</p>
            <div className="action-row" style={{ justifyContent: 'flex-end' }}>
              <button className="btn secondary" onClick={() => setModal(null)}>Cancel</button>
              <button className="btn primary" onClick={() => setModal(null)}>Confirm</button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
