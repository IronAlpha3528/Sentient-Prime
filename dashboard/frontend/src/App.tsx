import { Navigate, Route, Routes } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import AIReasoning from './pages/AIReasoning'
import ApprovalQueue from './pages/ApprovalQueue'
import AuditLog from './pages/AuditLog'
import Incidents from './pages/Incidents'
import IncidentTimeline from './pages/IncidentTimeline'
import Overview from './pages/Overview'
import ThreatGraphPage from './pages/ThreatGraphPage'

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/graph" element={<ThreatGraphPage />} />
          <Route path="/reasoning/:id" element={<AIReasoning />} />
          <Route path="/timeline/:id" element={<IncidentTimeline />} />
          <Route path="/approval-queue" element={<ApprovalQueue />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
