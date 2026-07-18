import type { AuditEntry } from '../api/client'

const tone = (event: string) => event === 'DETECTION' ? 'var(--warning)' : event === 'HYPOTHESIS_GENERATED' ? 'var(--info)' : event === 'SOAR_EXECUTED' ? 'var(--safe)' : event === 'ESCALATED' ? 'var(--danger)' : 'var(--muted-2)'

export default function AuditFeed({ entries, page = false }: { entries: AuditEntry[]; page?: boolean }) {
  return (
    <div className={page ? 'audit-page' : 'audit-feed'}>
      {page && <div style={{ marginBottom: 14 }}><span className="badge safe">CHAIN VERIFIED OK</span></div>}
      {entries.map((entry) => (
        <div className="audit-line" key={`${entry.timestamp}-${entry.event_type}`}>
          [{entry.timestamp}] <span style={{ color: tone(entry.event_type) }}>{entry.event_type.padEnd(20, ' ')}</span> {entry.incident_id} Hash: 0x{entry.hash}
        </div>
      ))}
    </div>
  )
}
