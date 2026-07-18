import type { ReasoningOutput } from '../api/client'

export default function PredictionFlow({ prediction }: { prediction: ReasoningOutput['prediction'] }) {
  return (
    <section className="card">
      <h2>Attack Prediction</h2>
      <div className="prediction-flow">
        <div className="flow-node"><span>Current Stage</span><strong>{prediction.current_stage}</strong></div>
        <div className="flow-arrow">-&gt;</div>
        <div className="flow-node"><span>Next Stage</span><strong>{prediction.next_stage}</strong></div>
        <div className="flow-arrow">-&gt;</div>
        <div className="flow-node"><span>Likely Target</span><strong>{prediction.likely_target}</strong></div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
        <div className="data-box"><span>Current Technique</span><strong className="mono">{prediction.current_technique}</strong></div>
        <div className="data-box"><span>Next Technique</span><strong className="mono">{prediction.next_technique}</strong></div>
        <div className="data-box"><span>Time Estimate</span><strong className="mono">{prediction.time_estimate}</strong></div>
      </div>
      <div className="breadcrumb" style={{ marginTop: 14 }}>
        {prediction.predicted_path.map((node, index) => (
          <span key={node} className="mono subtle">{index > 0 ? ' / ' : ''}{node}</span>
        ))}
      </div>
    </section>
  )
}
