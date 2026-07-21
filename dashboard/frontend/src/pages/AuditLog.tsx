import { useEffect, useState } from 'react'
import { getAuditLog, type AuditEntry } from '../api/client'
import AuditFeed from '../components/AuditFeed'

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  useEffect(() => { getAuditLog().then(setEntries) }, [])

  return (
    <div>
      <div className="page-header">
        <div>
          <p className="eyebrow">TAMPER-EVIDENT LEDGER</p>
          <h1>Cryptographic Audit Log</h1>
          <p className="subtle">Cryptographically hash-chained evidence of all AI detections, inferences, honeypot events, and SOAR executions.</p>
        </div>
      </div>
      <AuditFeed entries={entries} page />
    </div>
  )
}
