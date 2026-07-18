import type { Hypothesis } from '../api/client'

export default function HypothesisCard({ hypothesis }: { hypothesis: Hypothesis }) {
  const tone = hypothesis.is_malicious ? 'var(--danger)' : 'var(--safe)'
  return (
    <article className="card hypothesis">
      <div className="hypothesis-bar" style={{ background: tone }} />
      <div className="hypothesis-body">
        <div className="hypothesis-top">
          <div>
            <h3>{hypothesis.title}</h3>
            <p className="subtle">{hypothesis.description}</p>
          </div>
          <strong className="mono" style={{ color: tone }}>{Math.round(hypothesis.confidence * 100)}%</strong>
        </div>
        <div className="progress"><div className="progress-fill" style={{ width: `${hypothesis.confidence * 100}%`, background: tone }} /></div>
        <div className="tech-row">
          {hypothesis.mitre_techniques.length ? hypothesis.mitre_techniques.map((tech) => <span className="badge neutral" key={tech}>{tech}</span>) : <span className="badge safe">BENIGN PATH</span>}
        </div>
        <ul className="evidence-list">
          {hypothesis.supporting_evidence.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </div>
    </article>
  )
}
