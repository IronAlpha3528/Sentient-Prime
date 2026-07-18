export type IncidentStatus = 'ACTIVE' | 'ESCALATED' | 'RESOLVED'

export interface Incident {
  incident_id: string
  timestamp: string
  status: IncidentStatus
  unified_threat_score: number
  target_asset: string
  attack_class: string
  entities: {
    users: string[]
    hosts: string[]
    ips: string[]
    ot_assets: string[]
  }
}

export interface Hypothesis {
  title: string
  confidence: number
  is_malicious: boolean
  description: string
  mitre_techniques: string[]
  supporting_evidence: string[]
}

export interface ReasoningOutput {
  incident_id: string
  story: { narrative: string; domains_involved: string[] }
  hypotheses: Hypothesis[]
  prediction: {
    current_stage: string
    current_technique: string
    next_stage: string
    next_technique: string
    likely_target: string
    predicted_path: string[]
    time_estimate: string
  }
  deception_strategy: {
    should_deploy: boolean
    hypothesis_to_test: string
    decoy_type: string
    placement_node: string
    observation_window_minutes: number
    rationale: string
  }
  response_plan: {
    recommended_actions: Array<{
      action: string
      target: string
      containment_score: number
      business_impact: number
      composite_score: number
    }>
    routing_decision: 'SOAR_AUTO' | 'HUMAN_ESCALATION'
    policy_gate_passed: boolean
    dry_run_warnings: string[]
  }
}

export interface TopologyNode {
  id: string
  label: string
  criticality: number
  zone: string
  status: 'normal' | 'compromised' | 'at_risk'
  x?: number
  y?: number
}

export interface TopologyEdge { source: string; target: string }
export interface Topology {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  attack_path: string[]
  honeypot_placements: Array<{ node_id: string; decoy_type: string; status: string }>
}

export interface AuditEntry {
  timestamp: string
  event_type: string
  incident_id: string
  hash: string
}

export const getIncidents = async (): Promise<Incident[]> => [
  {
    incident_id: 'INC-102',
    timestamp: '2025-07-17T14:32:00Z',
    status: 'ACTIVE',
    unified_threat_score: 0.91,
    target_asset: 'admin_workstation',
    attack_class: 'lateral_movement',
    entities: { users: ['U101'], hosts: ['ENG-WS-01', 'SERVER-07'], ips: ['10.0.1.20', '10.0.2.17'], ot_assets: [] },
  },
  {
    incident_id: 'INC-103',
    timestamp: '2025-07-17T14:45:00Z',
    status: 'ESCALATED',
    unified_threat_score: 0.62,
    target_asset: 'web_server',
    attack_class: 'reconnaissance',
    entities: { users: ['U204'], hosts: ['DMZ-01'], ips: ['192.168.1.55'], ot_assets: [] },
  },
  {
    incident_id: 'INC-097',
    timestamp: '2025-07-17T13:10:00Z',
    status: 'RESOLVED',
    unified_threat_score: 0.34,
    target_asset: 'dmz_server',
    attack_class: 'benign',
    entities: { users: ['U042'], hosts: ['DMZ-01'], ips: [], ot_assets: [] },
  },
]

export const getReasoning = async (_id = 'INC-102'): Promise<ReasoningOutput> => ({
  incident_id: 'INC-102',
  story: {
    narrative:
      "User U101 authenticated to 12 new hosts within a 2-hour window, including SERVER-07 which hosts the internal HR database. Simultaneously, network telemetry detected infiltration-class traffic from 10.0.1.20. Endpoint telemetry on ENG-WS-01 shows a suspicious process chain: WINWORD.EXE -> powershell.exe -> rundll32.exe with encoded PowerShell commands matching Sigma rule 'Encoded PowerShell'. The combination of identity anomaly, network infiltration, and endpoint process chain strongly suggests a coordinated lateral movement operation following initial access via spear-phishing.",
    domains_involved: ['identity', 'network', 'endpoint'],
  },
  hypotheses: [
    {
      title: 'APT29 Lateral Movement via Spear-Phishing',
      confidence: 0.87,
      is_malicious: true,
      description: 'Initial access via weaponized Office document, followed by encoded PowerShell for C2, and lateral movement using compromised credentials.',
      mitre_techniques: ['T1566.001', 'T1059.001', 'T1021.001'],
      supporting_evidence: ['12 new host logins in 2h', 'Encoded PowerShell execution', 'Office child process spawning shell'],
    },
    {
      title: 'Insider Threat - Unauthorized Data Access',
      confidence: 0.52,
      is_malicious: true,
      description: 'Authorized user U101 accessing systems outside their normal scope, potentially for data exfiltration.',
      mitre_techniques: ['T1078', 'T1083'],
      supporting_evidence: ['12 new host logins', 'Access to HR database server'],
    },
    {
      title: 'Legitimate IT Administration Activity',
      confidence: 0.11,
      is_malicious: false,
      description: 'U101 is performing scheduled maintenance or authorized migration tasks requiring broad access.',
      mitre_techniques: [],
      supporting_evidence: ['U101 has admin privileges'],
    },
  ],
  prediction: {
    current_stage: 'Lateral Movement',
    current_technique: 'T1021.001 - Remote Desktop Protocol',
    next_stage: 'Collection',
    next_technique: 'T1005 - Data from Local System',
    likely_target: 'db_server',
    predicted_path: ['admin_workstation', 'scada_gateway', 'plc_controller'],
    time_estimate: '30-60 minutes',
  },
  deception_strategy: {
    should_deploy: true,
    hypothesis_to_test: 'APT29 Lateral Movement via Spear-Phishing',
    decoy_type: 'Fake SMB Share with honeytoken document',
    placement_node: 'db_server',
    observation_window_minutes: 30,
    rationale: 'If the attacker is truly moving laterally toward the database, they will enumerate shares on db_server. A fake share containing a canary document will confirm the hypothesis with near-zero false positives.',
  },
  response_plan: {
    recommended_actions: [
      { action: 'isolate_host', target: 'ENG-WS-01', containment_score: 0.9, business_impact: 0.2, composite_score: 0.57 },
      { action: 'revoke_credential', target: 'U101', containment_score: 0.75, business_impact: 0.1, composite_score: 0.5 },
      { action: 'block_ip', target: '10.0.1.20', containment_score: 0.55, business_impact: 0.05, composite_score: 0.37 },
    ],
    routing_decision: 'SOAR_AUTO',
    policy_gate_passed: true,
    dry_run_warnings: ['Isolating ENG-WS-01 will disconnect 1 active user session.'],
  },
})

export const getTopology = async (): Promise<Topology> => ({
  nodes: [
    { id: 'internet', label: 'Internet', criticality: 0, zone: 'external', status: 'normal' },
    { id: 'dmz_server', label: 'DMZ Server', criticality: 1, zone: 'dmz', status: 'normal' },
    { id: 'web_server', label: 'Web Server', criticality: 2, zone: 'it', status: 'normal' },
    { id: 'app_server', label: 'App Server', criticality: 3, zone: 'it', status: 'normal' },
    { id: 'admin_workstation', label: 'Admin WS', criticality: 3, zone: 'it', status: 'compromised' },
    { id: 'db_server', label: 'DB Server', criticality: 4, zone: 'it', status: 'at_risk' },
    { id: 'scada_gateway', label: 'SCADA GW', criticality: 8, zone: 'ot_boundary', status: 'at_risk' },
    { id: 'plc_controller', label: 'PLC Controller', criticality: 10, zone: 'ot', status: 'normal' },
    { id: 'cooling_pump', label: 'Cooling Pump', criticality: 10, zone: 'ot', status: 'normal' },
    { id: 'sensor_array', label: 'Sensor Array', criticality: 10, zone: 'ot', status: 'normal' },
  ],
  edges: [
    { source: 'internet', target: 'dmz_server' },
    { source: 'dmz_server', target: 'web_server' },
    { source: 'web_server', target: 'app_server' },
    { source: 'app_server', target: 'db_server' },
    { source: 'app_server', target: 'admin_workstation' },
    { source: 'admin_workstation', target: 'scada_gateway' },
    { source: 'scada_gateway', target: 'plc_controller' },
    { source: 'plc_controller', target: 'cooling_pump' },
    { source: 'plc_controller', target: 'sensor_array' },
  ],
  attack_path: ['admin_workstation', 'scada_gateway', 'plc_controller'],
  honeypot_placements: [{ node_id: 'db_server', decoy_type: 'Fake SMB Share', status: 'active' }],
})

export const getAuditLog = async (): Promise<AuditEntry[]> => [
  { timestamp: '2025-07-17T14:32:01Z', event_type: 'DETECTION', incident_id: 'INC-102', hash: '8a9b3f...' },
  { timestamp: '2025-07-17T14:32:05Z', event_type: 'HYPOTHESIS_GENERATED', incident_id: 'INC-102', hash: 'c4d2e1...' },
  { timestamp: '2025-07-17T14:32:12Z', event_type: 'PREDICTION_COMPLETE', incident_id: 'INC-102', hash: 'f7a1b9...' },
  { timestamp: '2025-07-17T14:32:18Z', event_type: 'DECEPTION_DEPLOYED', incident_id: 'INC-102', hash: '2e8c4d...' },
  { timestamp: '2025-07-17T14:32:25Z', event_type: 'RESPONSE_PLANNED', incident_id: 'INC-102', hash: '91d3a7...' },
  { timestamp: '2025-07-17T14:32:30Z', event_type: 'SOAR_EXECUTED', incident_id: 'INC-102', hash: 'b5f8e2...' },
]

export const getMetrics = async () => ({
  mttd_minutes: 4.2,
  mttr_minutes: 12.8,
  incidents_today: 7,
  incidents_resolved: 5,
  incidents_escalated: 1,
  incidents_active: 1,
  automation_rate: 0.71,
  detector_scores: {
    network: { precision: 0.94, recall: 0.91 },
    identity: { precision: 0.88, recall: 0.85 },
    endpoint: { precision: 0.96, recall: 0.93 },
    ot: { precision: 0.92, recall: 0.89 },
  },
})
