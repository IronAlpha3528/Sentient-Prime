import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { getApprovalQueue } from '../api/client'

const items = [
  { label: 'Overview', path: '/', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { label: 'Incidents', path: '/incidents', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
  { label: 'Threat Graph', path: '/graph', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { label: 'AI Reasoning', path: '/reasoning/INC-GRAPH-001', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 01-2 2h-4a2 2 0 01-2-2v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
  { label: 'Approval Queue', path: '/approval-queue', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', badge: true },
  { label: 'Audit Log', path: '/audit', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01m-.01 4h.01' },
]

export default function Sidebar() {
  const [pendingCount, setPendingCount] = useState(0)

  useEffect(() => {
    const poll = () => getApprovalQueue().then((q) => setPendingCount(q.length)).catch(() => {})
    poll()
    const id = setInterval(poll, 20_000)
    return () => clearInterval(id)
  }, [])

  return (
    <aside className="sidebar">
      <div className="logo">
        <div className="logo-mark">SP</div>
        <div>
          <div className="logo-text">SENTIENT PRIME</div>
          <div style={{ fontSize: 9, color: 'var(--cyber-cyan)', letterSpacing: '1.5px', fontFamily: 'var(--font-hud)', marginTop: 2 }}>
            AUTONOMOUS DEFENSE
          </div>
        </div>
      </div>
      
      <nav className="nav">
        {items.map((item) => (
          <NavLink 
            key={item.label} 
            to={item.path} 
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <svg 
              className="nav-icon" 
              viewBox="0 0 24 24" 
              fill="none" 
              stroke="currentColor" 
              strokeWidth="2" 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              aria-hidden="true"
            >
              <path d={item.icon} />
            </svg>
            <span className="nav-label">{item.label}</span>
            {item.badge && pendingCount > 0 && (
              <span className="badge danger pulse" style={{ fontSize: 10, padding: '1px 7px' }}>
                {pendingCount}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <span className="status-dot" style={{ background: 'var(--matrix-green)' }} />
        <div>
          <div style={{ fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-hud)', fontSize: 11 }}>
            POLICY GATE 100%
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--text-subtle)' }}>
            v2.4 SOAR CORE ACTIVE
          </div>
        </div>
      </div>
    </aside>
  )
}
