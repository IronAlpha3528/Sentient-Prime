import { NavLink } from 'react-router-dom'

const items = [
  { label: 'Overview', path: '/', icon: 'M3 13h8V3H3v10Zm10 8h8V3h-8v18ZM3 21h8v-6H3v6Z' },
  { label: 'Incidents', path: '/incidents', icon: 'M4 4h16v4H4V4Zm0 6h16v10H4V10Zm3 3v2h7v-2H7Z' },
  { label: 'Threat Graph', path: '/graph', icon: 'M6 7a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm12 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 23a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm2-17 7 5M16 14l-7 5' },
  { label: 'AI Reasoning', path: '/reasoning/INC-102', icon: 'M12 3 4 7v10l8 4 8-4V7l-8-4Zm0 2.2L17.4 8 12 10.8 6.6 8 12 5.2ZM6 9.7l5 2.6v6.1l-5-2.5V9.7Zm7 8.7v-6.1l5-2.6v6.2l-5 2.5Z' },
  { label: 'Deception', path: '/reasoning/INC-102#deception', icon: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Zm0 4 4 1.5V11c0 2.9-1.6 5.6-4 7-2.4-1.4-4-4.1-4-7V7.5L12 6Z' },
  { label: 'Audit Log', path: '/audit', icon: 'M5 3h14v18H5V3Zm3 4h8V5H8v2Zm0 4h8V9H8v2Zm0 4h8v-2H8v2Z' },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="logo">
        <div className="logo-mark">SP</div>
        <div className="logo-text">SENTINEL PRIME</div>
      </div>
      <nav className="nav">
        {items.map((item) => (
          <NavLink key={item.label} to={item.path} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <svg className="nav-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d={item.icon} /></svg>
            <span className="nav-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-status"><span className="status-dot" /><span>System Online</span></div>
    </aside>
  )
}
