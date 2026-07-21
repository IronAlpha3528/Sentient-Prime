import {
  getAuditLog as getMockAuditLog,
  getIncidents as getMockIncidents,
  getMetrics as getMockMetrics,
  getReasoning as getMockReasoning,
  getTopology as getMockTopology,
  type AuditEntry,
  type Incident,
  type ReasoningOutput,
  type Topology,
} from './mockData'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? ''

async function requestJson<T>(path: string, fallback: () => Promise<T>, options?: RequestInit): Promise<T> {
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
      ...options,
    })
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`)
    }
    return (await response.json()) as T
  } catch (error) {
    console.warn(`API request failed for ${path}, using mock fallback:`, error)
    return fallback()
  }
}

export const getIncidents = (): Promise<Incident[]> => requestJson('/api/incidents', getMockIncidents)
export const getTopology = (): Promise<Topology> => requestJson('/api/topology', getMockTopology)
export const getAuditLog = (): Promise<AuditEntry[]> => requestJson('/api/audit-log', getMockAuditLog)
export const getMetrics = (): Promise<Awaited<ReturnType<typeof getMockMetrics>>> => requestJson('/api/metrics', getMockMetrics)
export const getReasoning = (id = 'INC-GRAPH-001'): Promise<ReasoningOutput> => requestJson(`/api/incidents/${id}/reasoning`, () => getMockReasoning(id))
export const getApprovalQueue = (): Promise<Incident[]> => requestJson('/api/approval-queue', getMockIncidents)
export const getActiveDecoys = (): Promise<unknown[]> => requestJson('/api/decoys', async () => [])

export interface TimelineEntry {
  timestamp: string
  event_type: string
  incident_id: string
  hash: string
  data: Record<string, any>
}
export const getIncidentTimeline = (id: string): Promise<TimelineEntry[]> => requestJson(`/api/incidents/${id}/timeline`, async () => [])

export async function runLiveAiPipeline(id: string): Promise<ReasoningOutput> {
  return requestJson(`/api/incidents/${id}/run-ai`, () => getMockReasoning(id), {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export async function approveIncident(id: string): Promise<{ status: string; actions: unknown[]; outcome: unknown }> {
  return requestJson(`/api/incidents/${id}/approve`, async () => ({ status: 'ok', actions: [], outcome: {} }), {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export async function rejectIncident(id: string): Promise<{ status: string; outcome: unknown }> {
  return requestJson(`/api/incidents/${id}/reject`, async () => ({ status: 'ok', outcome: {} }), {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export interface PipelineStageEvent {
  type: 'pipeline_start' | 'stage_start' | 'stage_complete' | 'pipeline_complete' | 'error'
  stage?: number
  name?: string
  description?: string
  result?: Record<string, unknown>
  message?: string
  [key: string]: unknown
}

/**
 * Streams the 3-stage AI pipeline via SSE (Fetch + ReadableStream).
 * Returns a cancel function — call it to abort the stream.
 */
export function streamAiPipeline(
  id: string,
  onEvent: (event: PipelineStageEvent) => void,
  onComplete: (result: ReasoningOutput) => void,
  onError: (msg: string) => void,
): () => void {
  const url = `${API_BASE}/api/incidents/${id}/run-ai-stream`
  const controller = new AbortController()

  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok || !res.body) { onError(`HTTP ${res.status}`); return }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let currentEvent = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() ?? ''
        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim()
          } else if (line.startsWith('data: ')) {
            try {
              const payload = JSON.parse(line.slice(6)) as PipelineStageEvent
              payload.type = currentEvent as PipelineStageEvent['type']
              onEvent(payload)
              if (currentEvent === 'pipeline_complete') onComplete(payload as unknown as ReasoningOutput)
              if (currentEvent === 'error') onError(payload.message ?? 'Unknown error')
            } catch { /* ignore malformed SSE frames */ }
            currentEvent = ''
          }
        }
      }
    })
    .catch((err) => { if ((err as Error)?.name !== 'AbortError') onError(String(err)) })

  return () => controller.abort()
}

export type {
  AuditEntry,
  Hypothesis,
  Incident,
  IncidentStatus,
  ReasoningOutput,
  Topology,
  TopologyEdge,
  TopologyNode,
} from './mockData'
