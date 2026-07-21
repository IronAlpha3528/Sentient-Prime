import type { Hypothesis } from '../api/client'

export default function HypothesisCard({ hypothesis }: { hypothesis: Hypothesis }) {
  const tone = hypothesis.is_malicious ? 'var(--danger)' : 'var(--safe)'
  const pct = Math.round(hypothesis.confidence * 100)

  return (
    <article className="card hypothesis" style={{ borderColor: hypothesis.is_malicious ? 'rgba(244, 63, 94, 0.25)' : 'var(--border)' }}>
      <div className="hypothesis-bar" style={{ background: tone }} />
      <div className="hypothesis-body">
        <div className="hypothesis-top">
          <div>
            <h3>{hypothesis.title}</h3>
            <p className="subtle">{hypothesis.description}</p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <strong className="mono" style={{ color: tone, fontSize: 20 }}>{pct}%</strong>
            <div style={{ fontSize: 10, color: 'var(--text-subtle)', textTransform: 'uppercase' }}>CONFIDENCE</div>
          </div>
        </div>

        <div className="progress">
          <div className="progress-fill" style={{ width: `${pct}%`, background: tone }} />
        </div>

        <div className="tech-row" style={{ marginTop: 12 }}>
          {hypothesis.mitre_techniques.length > 0 ? (
            hypothesis.mitre_techniques.map((tech) => (
              <span className="badge neutral" key={tech} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                🎯 {tech}
              </span>
            ))
          ) : (
            <span className="badge safe">✓ BENIGN EXPLANATION</span>
          )}
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
            SUPPORTING EVIDENCE
          </div>
          <ul className="evidence-list">
            {hypothesis.supporting_evidence.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
    </article>
  )
}
