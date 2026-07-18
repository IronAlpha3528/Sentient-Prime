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

const nodeColor = (status: string) => status === 'compromised' ? '#ef4444' : status === 'at_risk' ? '#f59e0b' : '#3f3f46'
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
      <div className="graph-title"><strong>CNI THREAT TOPOLOGY</strong><span>{full ? 'Interactive entity map' : 'Predicted lateral movement'}</span></div>
      <ForceGraph2D
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="#0b1020"
        cooldownTicks={80}
        nodeRelSize={1}
        linkWidth={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? 2.2 : 1}
        linkColor={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? '#ef4444' : 'rgba(255,255,255,0.08)'}
        linkDirectionalParticles={(link: any) => showAttackPath && attackLinks.has(`${link.source.id ?? link.source}->${link.target.id ?? link.target}`) ? 4 : 0}
        linkDirectionalParticleSpeed={0.006}
        linkDirectionalParticleWidth={2}
        onNodeHover={(node: any) => setHover(node ? { node, x: node.x ?? 0, y: node.y ?? 0 } : null)}
        onNodeClick={(node: any) => {
          onNodeSelect?.(node)
          if (node.status === 'compromised') navigate('/reasoning/INC-GRAPH-001')
        }}
        nodeCanvasObject={(node: any, ctx, globalScale) => {
          const size = 6 + node.criticality * 1.4
          const pulse = node.status === 'compromised' ? 0.75 + Math.sin(Date.now() / 320) * 0.25 : 1
          ctx.save()
          ctx.globalAlpha = pulse
          ctx.fillStyle = nodeColor(node.status)
          ctx.beginPath()
          ctx.arc(node.x, node.y, size, 0, Math.PI * 2)
          ctx.fill()
          ctx.globalAlpha = 1
          if (showOtBoundary && (node.zone === 'ot' || node.zone === 'ot_boundary')) {
            ctx.setLineDash([4, 4])
            ctx.strokeStyle = 'rgba(255,255,255,0.35)'
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.arc(node.x, node.y, size + 6, 0, Math.PI * 2)
            ctx.stroke()
            ctx.setLineDash([])
          }
          if (showHoneypots && honeypots.has(node.id)) {
            ctx.fillStyle = '#6366f1'
            ctx.beginPath()
            ctx.moveTo(node.x, node.y - size - 12)
            ctx.lineTo(node.x + 5, node.y - size - 7)
            ctx.lineTo(node.x, node.y - size - 2)
            ctx.lineTo(node.x - 5, node.y - size - 7)
            ctx.closePath()
            ctx.fill()
          }
          const label = node.label
          const fontSize = 10 / globalScale
          ctx.font = `${fontSize}px JetBrains Mono`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'top'
          ctx.fillStyle = '#a1a1aa'
          ctx.fillText(label, node.x, node.y + size + 7)
          ctx.restore()
        }}
      />
      {hover && (
        <div className="graph-tooltip" style={{ left: Math.min(width - 210, hover.x + width / 2 + 20), top: Math.max(20, hover.y + height / 2 - 20) }}>
          <div className="name">{hover.node.label}</div>
          <div>criticality: {hover.node.criticality}</div>
          <div>zone: {hover.node.zone}</div>
          <div>status: {hover.node.status}</div>
        </div>
      )}
    </div>
  )
}

