import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

/* ─── Config ─────────────────────────────────────────────────────────────── */
const TOTAL_DURATION = 4200 // ms before auto-dismiss
const SKIP_KEY = 'sp_intro_seen'

interface InitStep {
  label: string
  icon: string
  delay: number   // ms after mount
}

const INIT_STEPS: InitStep[] = [
  { label: 'Initializing AI Core',          icon: '⬡',  delay: 400  },
  { label: 'Loading Threat Intelligence',   icon: '◈',  delay: 800  },
  { label: 'Connecting SIEM Pipeline',      icon: '◇',  delay: 1200 },
  { label: 'Loading Network Detector',      icon: '🌐', delay: 1600 },
  { label: 'Loading Endpoint Detector',     icon: '💻', delay: 1900 },
  { label: 'Loading Identity Detector',     icon: '👤', delay: 2200 },
  { label: 'Loading OT Detector',           icon: '🏭', delay: 2500 },
]

/* ─── Particle field (canvas-free, pure CSS) ─────────────────────────────── */
function Particles() {
  const dots = useMemo(() =>
    Array.from({ length: 60 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: 1 + Math.random() * 2,
      dur: 3 + Math.random() * 5,
      delay: Math.random() * 4,
      opacity: 0.15 + Math.random() * 0.35,
    })), [])

  return (
    <div className="intro-particles" aria-hidden>
      {dots.map(d => (
        <span
          key={d.id}
          className="intro-particle"
          style={{
            left: `${d.x}%`,
            top: `${d.y}%`,
            width: d.size,
            height: d.size,
            opacity: d.opacity,
            animationDuration: `${d.dur}s`,
            animationDelay: `${d.delay}s`,
          }}
        />
      ))}
    </div>
  )
}

/* ─── Scan-line overlay ──────────────────────────────────────────────────── */
function ScanLines() {
  return <div className="intro-scanlines" aria-hidden />
}

/* ─── Network graph mini-visualization ───────────────────────────────────── */
function MiniGraph() {
  const nodes = useMemo(() => [
    { x: 50, y: 50 },
    { x: 25, y: 30 },
    { x: 75, y: 28 },
    { x: 20, y: 65 },
    { x: 80, y: 68 },
    { x: 38, y: 78 },
    { x: 62, y: 80 },
    { x: 50, y: 20 },
    { x: 15, y: 48 },
    { x: 85, y: 45 },
  ], [])

  const edges = useMemo(() => [
    [0,1],[0,2],[0,3],[0,4],[1,7],[2,7],[3,5],[4,6],[1,8],[2,9],
    [5,6],[8,3],[9,4],[0,5],[0,6],
  ], [])

  return (
    <motion.svg
      viewBox="0 0 100 100"
      className="intro-mini-graph"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.6, duration: 0.8 }}
    >
      {/* Edges */}
      {edges.map(([a, b], i) => (
        <motion.line
          key={`e${i}`}
          x1={nodes[a].x} y1={nodes[a].y}
          x2={nodes[b].x} y2={nodes[b].y}
          stroke="rgba(0,240,255,0.15)"
          strokeWidth={0.4}
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ delay: 0.8 + i * 0.06, duration: 0.5 }}
        />
      ))}

      {/* Attack path pulse */}
      {[[0,1],[1,8],[8,3],[3,5]].map(([a, b], i) => (
        <motion.line
          key={`ap${i}`}
          x1={nodes[a].x} y1={nodes[a].y}
          x2={nodes[b].x} y2={nodes[b].y}
          stroke="#ff0055"
          strokeWidth={0.6}
          strokeLinecap="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: [0, 0.9, 0.4] }}
          transition={{ delay: 2.0 + i * 0.15, duration: 0.6 }}
        />
      ))}

      {/* Nodes */}
      {nodes.map((n, i) => (
        <motion.circle
          key={`n${i}`}
          cx={n.x} cy={n.y}
          r={i === 0 ? 2 : 1.3}
          fill={i === 0 ? '#00f0ff' : i <= 2 ? '#ff0055' : '#38bdf8'}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.9 + i * 0.08, duration: 0.3, type: 'spring', stiffness: 200 }}
        />
      ))}

      {/* Central glow */}
      <motion.circle
        cx={50} cy={50} r={5}
        fill="none"
        stroke="rgba(0,240,255,0.25)"
        strokeWidth={0.3}
        initial={{ scale: 0 }}
        animate={{ scale: [1, 1.8, 1], opacity: [0.4, 0, 0.4] }}
        transition={{ delay: 1.2, duration: 2, repeat: Infinity }}
      />
    </motion.svg>
  )
}

/* ─── Init Sequence Step ─────────────────────────────────────────────────── */
function StepLine({ step, active }: { step: InitStep; active: boolean }) {
  return (
    <motion.div
      className="intro-step"
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25 }}
    >
      <span className="intro-step-icon">{step.icon}</span>
      <span className="intro-step-label">{step.label}</span>
      <span className="intro-step-status">
        {active ? (
          <motion.span
            className="intro-check"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 400, damping: 15 }}
          >
            ✓
          </motion.span>
        ) : (
          <span className="intro-spinner" />
        )}
      </span>
    </motion.div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Main IntroAnimation                                                       */
/* ═══════════════════════════════════════════════════════════════════════════ */
export default function IntroAnimation({ children }: { children: React.ReactNode }) {
  const [show, setShow] = useState(() => {
    if (typeof window === 'undefined') return false
    return !sessionStorage.getItem(SKIP_KEY)
  })
  const [completedSteps, setCompletedSteps] = useState<number[]>([])
  const [visibleSteps, setVisibleSteps] = useState<number[]>([])
  const [phase, setPhase] = useState<'logo' | 'init' | 'online' | 'done'>('logo')

  // Schedule the init steps
  useEffect(() => {
    if (!show) return
    const timers: ReturnType<typeof setTimeout>[] = []

    // Show steps sequentially
    INIT_STEPS.forEach((step, i) => {
      timers.push(setTimeout(() => setVisibleSteps(prev => [...prev, i]), step.delay))
      timers.push(setTimeout(() => setCompletedSteps(prev => [...prev, i]), step.delay + 280))
    })

    // Phase transitions
    timers.push(setTimeout(() => setPhase('init'), 300))
    timers.push(setTimeout(() => setPhase('online'), 3000))
    timers.push(setTimeout(() => {
      setPhase('done')
      sessionStorage.setItem(SKIP_KEY, '1')
      setTimeout(() => setShow(false), 600)
    }, TOTAL_DURATION))

    return () => timers.forEach(clearTimeout)
  }, [show])

  const handleSkip = useCallback(() => {
    sessionStorage.setItem(SKIP_KEY, '1')
    setPhase('done')
    setTimeout(() => setShow(false), 300)
  }, [])

  return (
    <>
      <AnimatePresence>
        {show && (
          <motion.div
            className="intro-overlay"
            initial={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 1.04 }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          >
            <ScanLines />
            <Particles />

            {/* Hex grid background pattern */}
            <div className="intro-hex-grid" aria-hidden />

            {/* Central content */}
            <div className="intro-center">
              {/* Logo */}
              <motion.div
                className="intro-logo-wrap"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                <div className="intro-logo-shield">
                  <svg viewBox="0 0 60 68" className="intro-shield-svg">
                    <motion.path
                      d="M30 2 L56 16 L56 42 Q56 56 30 66 Q4 56 4 42 L4 16 Z"
                      fill="none"
                      stroke="url(#shieldGrad)"
                      strokeWidth="1.5"
                      strokeLinejoin="round"
                      initial={{ pathLength: 0 }}
                      animate={{ pathLength: 1 }}
                      transition={{ duration: 1.2, ease: 'easeInOut' }}
                    />
                    <defs>
                      <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#00f0ff" />
                        <stop offset="100%" stopColor="#9d4edd" />
                      </linearGradient>
                    </defs>
                    <motion.text
                      x="30" y="40"
                      textAnchor="middle"
                      fill="#00f0ff"
                      fontSize="20"
                      fontFamily="Orbitron, sans-serif"
                      fontWeight="700"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.8 }}
                    >
                      SP
                    </motion.text>
                  </svg>
                </div>

                <motion.h1
                  className="intro-title"
                  initial={{ opacity: 0, letterSpacing: '0.5em' }}
                  animate={{ opacity: 1, letterSpacing: '0.2em' }}
                  transition={{ delay: 0.3, duration: 0.8 }}
                >
                  <span className="intro-title-glitch" data-text="SENTINEL-PRIME">SENTINEL-PRIME</span>
                </motion.h1>

                <motion.p
                  className="intro-subtitle"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 0.6 }}
                  transition={{ delay: 0.6, duration: 0.5 }}
                >
                  Autonomous Cyber Defense Platform
                </motion.p>
              </motion.div>

              {/* Mini Graph */}
              <MiniGraph />

              {/* Init Sequence */}
              <motion.div
                className="intro-init-list"
                initial={{ opacity: 0 }}
                animate={{ opacity: phase === 'logo' ? 0 : 1 }}
                transition={{ duration: 0.3 }}
              >
                {visibleSteps.map(i => (
                  <StepLine
                    key={i}
                    step={INIT_STEPS[i]}
                    active={completedSteps.includes(i)}
                  />
                ))}
              </motion.div>

              {/* "Online" Badge */}
              <AnimatePresence>
                {phase === 'online' && (
                  <motion.div
                    className="intro-online-badge"
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 1.1 }}
                    transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                  >
                    <span className="intro-online-dot" />
                    SENTINEL-PRIME ONLINE
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Skip Button */}
            <motion.button
              className="intro-skip"
              onClick={handleSkip}
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.5 }}
              whileHover={{ opacity: 1 }}
              transition={{ delay: 1 }}
            >
              SKIP ›
            </motion.button>

            {/* Bottom status bar */}
            <div className="intro-bottom-bar">
              <span className="intro-bottom-left mono">
                v2.1.0 — CLASSIFIED // SOC-LEVEL-1
              </span>
              <motion.div
                className="intro-progress-track"
                initial={{ width: 0 }}
              >
                <motion.div
                  className="intro-progress-fill"
                  initial={{ width: '0%' }}
                  animate={{ width: '100%' }}
                  transition={{ duration: TOTAL_DURATION / 1000, ease: 'linear' }}
                />
              </motion.div>
              <span className="intro-bottom-right mono">
                {phase === 'online' ? 'READY' : 'INITIALIZING'}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Render children immediately so they load behind the overlay */}
      {children}
    </>
  )
}
