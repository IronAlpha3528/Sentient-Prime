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
    console.error(`API request failed for ${path}:`, error)
    throw error
    // return fallback()
  }
}

export const getIncidents = (): Promise<Incident[]> => requestJson('/api/incidents', getMockIncidents)
export const getTopology = (): Promise<Topology> => requestJson('/api/topology', getMockTopology)
export const getAuditLog = (): Promise<AuditEntry[]> => requestJson('/api/audit-log', getMockAuditLog)
export const getMetrics = (): Promise<Awaited<ReturnType<typeof getMockMetrics>>> => requestJson('/api/metrics', getMockMetrics)
export const getReasoning = (id = 'INC-GRAPH-001'): Promise<ReasoningOutput> => requestJson(`/api/incidents/${id}/reasoning`, () => getMockReasoning(id))

export async function runLiveAiPipeline(id: string): Promise<ReasoningOutput> {
  return requestJson(`/api/incidents/${id}/run-ai`, () => getMockReasoning(id), {
    method: 'POST',
    body: JSON.stringify({}),
  })
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
