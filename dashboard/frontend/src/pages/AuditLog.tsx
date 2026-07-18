import { useEffect, useState } from 'react'
import { getAuditLog, type AuditEntry } from '../api/client'
import AuditFeed from '../components/AuditFeed'

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  useEffect(() => { getAuditLog().then(setEntries) }, [])
  return (
    <div>
      <div className="page-header"><div><p className="eyebrow">Tamper-Evident Ledger</p><h1>Audit Log</h1><p className="subtle">Hash-chained evidence of detections, reasoning, deception, and SOAR actions.</p></div></div>
      <AuditFeed entries={entries} page />
    </div>
  )
}
