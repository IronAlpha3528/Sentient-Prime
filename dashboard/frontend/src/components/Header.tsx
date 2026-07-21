import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { getApprovalQueue } from '../api/client'

export default function Header() {
  const [time, setTime] = useState<string>(new Date().toLocaleTimeString())
  const [pendingCount, setPendingCount] = useState<number>(0)
  const [isRefreshing, setIsRefreshing] = useState(false)

  const fetchQueue = () => {
    getApprovalQueue().then((queue) => setPendingCount(queue.length)).catch(() => {})
  }

  useEffect(() => {
    fetchQueue()
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString())
    }, 1000)
    const queuePoll = setInterval(fetchQueue, 15000)
    return () => {
      clearInterval(timer)
      clearInterval(queuePoll)
    }
  }, [])

  const handleRefresh = () => {
    setIsRefreshing(true)
    fetchQueue()
    setTimeout(() => setIsRefreshing(false), 600)
  }

  return (
    <header className="top-header">
      <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
        <div className="header-status-badge">
          <span className="status-dot pulse" />
          <span className="font-hud">SENTIENT PRIME CORE</span>
          <span style={{ color: 'var(--text-subtle)', marginLeft: 2 }}>[SYSTEM ONLINE]</span>
        </div>

        <div className="badge neutral mono" style={{ fontSize: 11, gap: 6 }}>
          <span style={{ color: 'var(--cyber-cyan)' }}>PING:</span> 14ms &nbsp;|&nbsp;
          <span style={{ color: 'var(--matrix-green)' }}>AUDIT LEDGER:</span> VERIFIED
        </div>
      </div>

      <div className="header-actions">
        {pendingCount > 0 && (
          <NavLink to="/approval-queue" className="badge danger pulse" style={{ cursor: 'pointer', padding: '6px 14px', fontSize: 11, fontFamily: 'var(--font-hud)' }}>
            ⚡ {pendingCount} PENDING ACTION{pendingCount > 1 ? 'S' : ''}
          </NavLink>
        )}

        <div className="mono" style={{ fontSize: 13, color: 'var(--cyber-cyan)', display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(0, 240, 255, 0.05)', padding: '5px 12px', borderRadius: 8, border: '1px solid var(--border)' }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          <span className="font-hud" style={{ fontSize: 12 }}>{time}</span>
        </div>

        <button 
          className="btn secondary" 
          onClick={handleRefresh}
          title="Refresh dashboard telemetry"
          style={{ height: 36, padding: '0 12px', fontSize: 12 }}
        >
          <svg 
            width="14" 
            height="14" 
            viewBox="0 0 24 24" 
            fill="none" 
            stroke="currentColor" 
            strokeWidth="2"
            style={{ transition: 'transform 600ms ease', transform: isRefreshing ? 'rotate(360deg)' : 'none' }}
          >
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
          </svg>
        </button>
      </div>
    </header>
  )
}
