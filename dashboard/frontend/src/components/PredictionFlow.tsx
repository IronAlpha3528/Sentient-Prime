import type { ReasoningOutput } from '../api/client'

export default function PredictionFlow({ prediction }: { prediction: ReasoningOutput['prediction'] }) {
  return (
    <section className="card accent-primary">
      <h2>Attack Prediction & Lateral Movement</h2>
      
      <div className="prediction-flow">
        <div className="flow-node">
          <span>CURRENT STAGE</span>
          <strong style={{ color: 'var(--warning)', fontSize: 16 }}>{prediction.current_stage}</strong>
        </div>
        <div className="flow-arrow">➔</div>
        <div className="flow-node">
          <span>NEXT PREDICTED STAGE</span>
          <strong style={{ color: 'var(--danger)', fontSize: 16 }}>{prediction.next_stage}</strong>
        </div>
        <div className="flow-arrow">➔</div>
        <div className="flow-node">
          <span>HIGH VALUE TARGET</span>
          <strong style={{ color: 'var(--primary)', fontSize: 16 }}>{prediction.likely_target}</strong>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
        <div className="data-box">
          <span>Current Technique</span>
          <strong className="mono" style={{ color: 'var(--warning)' }}>{prediction.current_technique}</strong>
        </div>
        <div className="data-box">
          <span>Next Technique</span>
          <strong className="mono" style={{ color: 'var(--danger)' }}>{prediction.next_technique}</strong>
        </div>
        <div className="data-box">
          <span>Estimated Window</span>
          <strong className="mono" style={{ color: 'var(--primary)' }}>{prediction.time_estimate}</strong>
        </div>
      </div>

      <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
        <div style={{ fontSize: 11, color: 'var(--text-subtle)', marginBottom: 8, letterSpacing: '1px', fontWeight: 700 }}>
          PREDICTED LATERAL PATHWAY
        </div>
        <div className="breadcrumb">
          {prediction.predicted_path.map((node, index) => (
            <div key={node} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {index > 0 && <span style={{ color: 'var(--text-subtle)' }}>→</span>}
              <span className="badge neutral mono" style={{ fontSize: 12, padding: '4px 10px' }}>
                {node}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
