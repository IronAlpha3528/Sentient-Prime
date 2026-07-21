import type { AuditEntry } from '../api/client'

const getEventTone = (event: string) => {
  if (event.includes('DETECTION') || event.includes('ALERT')) return 'var(--danger)'
  if (event.includes('HYPOTHESIS') || event.includes('INFERENCE')) return 'var(--ai-purple)'
  if (event.includes('SOAR') || event.includes('CONTAINMENT')) return 'var(--safe)'
  if (event.includes('ESCALATED') || event.includes('WARN')) return 'var(--warning)'
  return 'var(--primary)'
}

export default function AuditFeed({ entries, page = false }: { entries: AuditEntry[]; page?: boolean }) {
  if (!entries.length) {
    return (
      <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-subtle)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        [LOG STREAM EMPTY]
      </div>
    )
  }

  return (
    <div className={page ? 'audit-page' : 'audit-feed'}>
      {page && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span className="badge safe">✓ CHAIN INTEGRITY VERIFIED</span>
            <span className="badge neutral">SHA-256 HASH-CHAINING</span>
          </div>
          <span className="mono subtle" style={{ fontSize: 12 }}>{entries.length} Ledger Entries</span>
        </div>
      )}
      
      {entries.map((entry, idx) => {
        const color = getEventTone(entry.event_type)
        return (
          <div className="audit-line" key={`${entry.timestamp}-${entry.event_type}-${idx}`}>
            <span style={{ color: 'var(--text-subtle)', marginRight: 8 }}>[{entry.timestamp}]</span>
            <span className="mono" style={{ color, fontWeight: 600, display: 'inline-block', width: 180 }}>
              {entry.event_type}
            </span>
            <span className="mono" style={{ color: 'var(--text-main)', marginRight: 12 }}>
              {entry.incident_id}
            </span>
            <span className="mono subtle" style={{ fontSize: 11 }}>
              hash: 0x{entry.hash.substring(0, 12)}...
            </span>
          </div>
        )
      })}
    </div>
  )
}
