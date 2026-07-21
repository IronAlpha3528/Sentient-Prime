import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { useNavigate } from 'react-router-dom'
import type { Topology, TopologyNode } from '../api/client'

type Props = {
  topology: Topology
  height?: number
  full?: boolean
  showAttackPath?: boolean
  showHoneypots?: boolean
  showOtBoundary?: boolean
  zoneFilter?: string
  onNodeSelect?: (node: TopologyNode) => void
}

const nodeColor = (status: string) => status === 'compromised' ? '#f43f5e' : status === 'at_risk' ? '#fbbf24' : '#38bdf8'
const endpointId = (endpoint: unknown) => typeof endpoint === 'object' && endpoint !== null && 'id' in endpoint ? String((endpoint as { id: string }).id) : String(endpoint)

export default function ThreatGraph({ topology, height = 520, full = false, showAttackPath = true, showHoneypots = true, showOtBoundary = true, zoneFilter = 'all', onNodeSelect }: Props) {
  const navigate = useNavigate()
  const wrapRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(900)
  const [hover, setHover] = useState<{ node: TopologyNode; x: number; y: number } | null>(null)

  useEffect(() => {
    const sync = () => setWidth(wrapRef.current?.clientWidth ?? 900)
    sync()
    window.addEventListener('resize', sync)
    return () => window.removeEventListener('resize', sync)
  }, [])

  const attackLinks = useMemo(() => new Set(topology.attack_path.slice(0, -1).map((id, i) => `${id}->${topology.attack_path[i + 1]}`)), [topology.attack_path])
  const honeypots = useMemo(() => new Map(topology.honeypot_placements.map((h) => [h.node_id, h])), [topology.honeypot_placements])
  const graphData = useMemo(() => {
    const nodes = zoneFilter === 'all' ? topology.nodes : topology.nodes.filter((node) => node.zone === zoneFilter)
    const ids = new Set(nodes.map((node) => node.id))
    const links = topology.edges
      .map((edge) => ({ source: endpointId(edge.source), target: endpointId(edge.target) }))
      .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
    return { nodes: nodes.map((node) => ({ ...node })), links }
  }, [topology, zoneFilter])

  return (
    <div className="graph-card card" ref={wrapRef} style={{ height }}>
      <div className="graph-title">
        <strong>CNI THREAT TOPOLOGY MAP</strong>
        <span>{full ? 'Interactive Network Mesh' : 'Predicted Lateral Path & Honeypots'}</span>
      </div>

      {/* Floating Legend Overlay */}
      <div style={{ position: 'absolute', top: 16, left: 16, zIndex: 10, display: 'flex', gap: 12, background: 'rgba(7,10,20,0.85)', backdropFilter: 'blur(8px)', padding: '6px 14px', borderRadius: 9999, border: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f43f5e' }} />
          <span>Compromised</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#fbbf24' }} />
          <span>At Risk</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8' }} />
          <span>Normal</span>
        </div>
        {showHoneypots && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ai-purple)' }}>
            <span>◆ Honeypot</span>
          </div>
        )}
      </div>

      <ForceGraph2D
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="transparent"
        cooldownTicks={80}
        nodeRelSize={1}
        linkWidth={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? 3 : 1.5}
        linkColor={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? '#f43f5e' : 'rgba(255,255,255,0.2)'}
        linkDirectionalParticles={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? 6 : 0}
        linkDirectionalParticleSpeed={0.008}
        linkDirectionalParticleWidth={4}
        linkDirectionalParticleColor={() => '#f43f5e'}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        onNodeHover={(node: any) => setHover(node ? { node, x: node.x ?? 0, y: node.y ?? 0 } : null)}
        onNodeClick={(node: any) => {
          onNodeSelect?.(node)
          if (node.status === 'compromised') navigate('/reasoning/INC-GRAPH-001')
        }}
        nodeCanvasObject={(node: any, ctx, globalScale) => {
          const baseSize = 6 + node.criticality * 1.4
          const size = baseSize * 0.6
          const pulse = node.status === 'compromised' ? 0.8 + Math.sin(Date.now() / 300) * 0.2 : 1

          
          ctx.save()
          ctx.globalAlpha = pulse

          // Glow ring for compromised nodes
          if (node.status === 'compromised') {
            ctx.shadowColor = '#f43f5e'
            ctx.shadowBlur = 12
          }

          ctx.fillStyle = nodeColor(node.status)
          ctx.beginPath()
          ctx.arc(node.x, node.y, size, 0, Math.PI * 2)
          ctx.fill()
          ctx.globalAlpha = 1
          ctx.shadowBlur = 0

          if (showOtBoundary && (node.zone === 'ot' || node.zone === 'ot_boundary')) {
            ctx.setLineDash([3, 3])
            ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)'
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.arc(node.x, node.y, size + 6, 0, Math.PI * 2)
            ctx.stroke()
            ctx.setLineDash([])
          }

          if (showHoneypots && honeypots.has(node.id)) {
            ctx.fillStyle = '#c084fc'
            ctx.beginPath()
            ctx.moveTo(node.x, node.y - size - 14)
            ctx.lineTo(node.x + 6, node.y - size - 8)
            ctx.lineTo(node.x, node.y - size - 2)
            ctx.lineTo(node.x - 6, node.y - size - 8)
            ctx.closePath()
            ctx.fill()
          }

          const label = node.label
          const fontSize = 11 / globalScale
          ctx.font = `${fontSize}px Plus Jakarta Sans, sans-serif`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'top'
          ctx.fillStyle = '#cbd5e1'
          ctx.fillText(label, node.x, node.y + size + 6)
          ctx.restore()
        }}
      />

      {hover && (
        <div className="graph-tooltip" style={{ left: Math.min(width - 220, Math.max(20, hover.x + width / 2 + 20)), top: Math.max(20, hover.y + height / 2 - 20) }}>
          <div className="name">{hover.node.label}</div>
          <div>ID: <span className="mono">{hover.node.id}</span></div>
          <div>Criticality: <span className="mono">{hover.node.criticality}/10</span></div>
          <div>Zone: <span className="mono">{hover.node.zone}</span></div>
          <div>Status: <span style={{ color: nodeColor(hover.node.status), fontWeight: 700 }}>{hover.node.status}</span></div>
        </div>
      )}
    </div>
  )
}
