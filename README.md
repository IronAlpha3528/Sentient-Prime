# Sentinel — Agentic AI Cyber Resilience Platform

An AI-powered cyber resilience system for critical infrastructure that combines **agentic log analysis** (to catch ransomware, data corruption, and malicious activity from SIEM telemetry) with a **deception layer** (honeypots/honeytokens) that gives a near-zero-false-positive "ground truth" signal of compromise.

Detected and confirmed incidents are now reasoned over using a **multi-hypothesis, risk-weighted decision pipeline** — generating several competing explanations for an incident, ranking possible containment actions by a transparent score that weighs security benefit against operational cost, testing the chosen action in a **dry run** before committing, and **monitoring the outcome** so the system improves with every incident.

Built for: AI-powered Cyber Resilience for Critical National Infrastructure (hackathon challenge — behavioral anomaly detection, APT attribution, autonomous incident response).

---

## 1. The problem we're solving

Most public-sector SOCs discover breaches **weeks after** initial compromise because:

- Detection relies on known malware signatures, which fail against low-and-slow APTs.
- SIEMs generate huge volumes of alerts with high false-positive rates, causing alert fatigue.
- A single alert is usually collapsed into a single verdict, with no structured way to weigh competing explanations or the operational cost of acting on a wrong one.
- There's no fast, high-confidence way to confirm "this system is actually compromised" before damage spreads.
- Once a breach is confirmed, no one knows what *else* the attacker touched, and there's little visibility into whether the response actually worked.

**Our approach:** plant deliberate tripwires (honeypots/honeytokens) that give a near-certain compromise signal, pair that with agentic log analysis for ransomware/corruption/malicious-activity patterns, and — instead of collapsing everything into one confidence score — reason over **multiple competing explanations**, rank containment options by a **transparent risk-weighted score**, test the top action in a **dry run**, and **monitor the outcome** before closing the loop.

---

## 2. How it works (end to end)

```
 ┌─────────────────────┐
 │   Log & SIEM Layer    │  Endpoint logs, network flow, auth logs,
 │  (Wazuh / ELK / etc.) │  file-integrity events, honeypot triggers
 └──────────┬───────────┘
            │
   ┌────────┴──────────┐
   ▼                    ▼
┌───────────────────┐  ┌──────────────────────────┐
│ Detection Agents    │  │ Honeypot / Deception Layer│
│ ransomware /        │  │ decoy creds, files,        │
│ corruption /        │  │ shares, OT/ICS endpoints   │
│ malicious activity  │  │ → near-certain compromise  │
└─────────┬──────────┘  └─────────────┬──────────────┘
          │  candidate signals        │ confirmed-touch events
          └─────────────┬─────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │  Hypothesis Generation Agent       │  Produces several competing
        │  (multi-hypothesis reasoning)      │  explanations per incident —
        │                                    │  e.g. "ransomware staging",
        │                                    │  "lateral-movement prep",
        │                                    │  "benign backup job" — each
        │                                    │  with its own confidence score
        │                                    │  and supporting evidence
        └─────────────────┬───────────────────┘
                           ▼
        ┌─────────────────────────────────┐
        │  Correlation & Attribution Agent   │  Maps the leading hypothesis
        │                                    │  to MITRE ATT&CK technique(s);
        │                                    │  builds a graph of what else
        │                                    │  this entity touched recently
        └─────────────────┬───────────────────┘
                           ▼
        ┌─────────────────────────────────┐
        │  Risk Scoring & Action Ranking      │  Scores each candidate
        │  (containment vs. business impact) │  containment action by
        │                                      │  weighing how well it
        │                                      │  contains the threat against
        │                                      │  its operational cost
        └─────────────────┬───────────────────┘
                           ▼
        ┌─────────────────────────────────┐
        │  Orchestration Agent                │  Dry-runs the top-ranked
        │  dry-run → policy gate → execute    │  action first (simulate +
        │                                      │  log predicted effect), then
        │                                      │  auto-executes if low blast
        │                                      │  radius & high confidence,
        │                                      │  else escalates to a human
        └─────────────────┬───────────────────┘
                           ▼
        ┌─────────────────────────────────┐
        │  Closed-loop Outcome Monitoring     │  Confirms the action actually
        │                                      │  worked (did the malicious
        │                                      │  activity stop?); feeds the
        │                                      │  result back into baselines
        │                                      │  and future hypothesis scoring
        └─────────────────┬───────────────────┘
                           ▼
        ┌─────────────────────────────────┐
        │  Tamper-evident Audit Ledger         │  Every hypothesis, score,
        │                                      │  dry-run, action, and outcome
        │                                      │  is recorded for review
        └─────────────────────────────────┘
```

### 2.1 The two ways an incident gets triggered

1. **Log-driven detection** — detection agents continuously score SIEM events for ransomware-like behavior (rapid file modification/encryption, shadow-copy deletion, entropy spikes), data corruption (unexpected checksum/integrity failures), or other malicious activity (suspicious process lineage, abnormal outbound connections). This path produces a *candidate* signal, not an automatic action.
2. **Honeypot-driven confirmation** — any touch on a decoy credential, file share, API key, or OT/ICS register is, by design, something no real user or process should ever do. This path is treated as **high-confidence ground truth** and can independently trigger investigation, or confirm a log-driven suspicion outright.

Both paths feed the same downstream pipeline below — a honeypot hit simply walks in with a much higher starting confidence than a log-only signal.

### 2.2 From signal to decision: multi-hypothesis reasoning

Rather than collapsing an incident into a single "malicious / benign" verdict, the **Hypothesis Generation Agent** proposes several plausible explanations at once, each grounded in the specific evidence available, each MITRE ATT&CK-anchored where applicable, and each carrying its own confidence score — including a benign explanation as one of the candidates. For example:

| ID | Hypothesis | Confidence |
|---|---|---|
| H1 | Ransomware staging (mass file modification + shadow-copy deletion) | 0.78 |
| H2 | Lateral-movement preparation (credential harvesting, no encryption yet) | 0.45 |
| H3 | Benign backup/maintenance job | 0.15 |

This matters because it keeps the system honest about uncertainty, gives the downstream agents richer input to reason over than a single number, and makes a far more convincing audit trail than "the model said 0.81."

### 2.3 Ranking responses: a transparent risk score

Once the leading hypothesis is established, candidate containment actions are ranked with a composite score that weighs containment effectiveness against the operational/business cost of taking that action:

```
Composite Score = (α × Containment Effectiveness) − (β × Business Impact)
```

`α` and `β` are tunable weights reflecting how aggressively the organisation wants to favor security over continuity. Example, with α = 0.7, β = 0.3:

| Rank | Action | Containment | Business Impact | Score |
|---|---|---|---|---|
| 1 | Isolate host | 0.90 | 0.20 | 0.57 |
| 2 | Revoke credential | 0.75 | 0.10 | 0.50 |
| 3 | Block IP/domain | 0.55 | 0.05 | 0.37 |
| 4 | Snapshot VM (forensic only) | 0.10 | 0.02 | 0.06 |
| 5 | Monitor only | 0.05 | 0.00 | 0.04 |

This replaces a flat "if confidence ≥ 0.9, isolate" rule with something a judge — or a real SOC lead — can actually interrogate and tune.

### 2.4 Safety before action: dry-run execution

The top-ranked action is never executed live on the first pass. The orchestration agent first runs it in **dry-run mode**: simulating the action, predicting its effect (which services would be disrupted, which sessions would be killed, which hosts would lose connectivity), and logging that prediction to the audit ledger — without actually touching the target system. Only once the dry-run confirms no unexpected critical-service dependency, **and** the risk score and blast radius clear their respective thresholds, does the action move to live execution (autonomously for low-blast-radius cases, or after human approval for anything broader).

### 2.5 Closing the loop: outcome monitoring

After a live action executes, a monitoring step rechecks the entity's behavior over a short follow-up window: did the suspicious file activity actually stop, did honeypot interactions cease, did the flagged process terminate. The outcome — success, partial success, or failure — is written back into the baseline store, which adjusts how much weight similar evidence combinations get in future hypothesis scoring. This is what lets the system get measurably better at telling true from false positives over time, instead of running the same static logic on incident #1 and incident #100.

---

## 3. What we need to build

| # | Component | What it does | Build effort |
|---|---|---|---|
| 0 | Offline training pipeline | Preprocess datasets, train Isolation Forest + XGBoost, build FAISS vector DB, compile Sigma rules | Medium |
| 1 | Log ingestion pipeline | Ship endpoint/network/auth logs into a central store | Low–Medium |
| 2 | Ransomware/corruption/malicious-activity detection agents | ML-assisted (Isolation Forest, XGBoost) + rule-based (Sigma, entropy, z-score) scoring of log patterns | Medium |
| 3 | Honeypot/honeytoken layer | Deploy decoys across IT and OT, capture interaction events | Low–Medium |
| 4 | Threat correlation engine | Signal fusion: merge anomaly scores + attack class + ATT&CK TTP match + co-occurrences | Medium |
| 5 | Hypothesis Generation Agent | Gemini Flash + FAISS ATT&CK RAG producing 2–4 confidence-scored competing explanations per incident | Medium |
| 6 | APT attribution + next-stage prediction | Map to known TTP chains, predict likely next technique, NetworkX 2-hop graph | Medium–High |
| 7 | Risk Scoring & Action Ranking module | Weighs containment effectiveness vs. business impact per candidate action | Low–Medium |
| 8 | Orchestration agent (dry-run + SOAR playbook) | Simulates, then auto-executes (confidence ≥0.75 + low blast radius) or escalates to human gate | Medium |
| 9 | Closed-loop outcome monitoring | Confirms actions worked; feeds results back into baselines | Medium |
| 10 | Audit ledger | Hash-chained, append-only record of every hypothesis, score, and action | Low |
| 11 | SOC Dashboard (React) | Live alert feed, TTP map, MTTD/MTTR metrics, hypothesis ladder, audit log | Medium |

### 3.1 Log ingestion pipeline
- **Tooling:** Wazuh or the ELK stack (Elasticsearch + Logstash/Beats + Kibana) for the SIEM layer; Sysmon/auditd for endpoint telemetry; Suricata/Zeek for network flow.
- **What to ingest:** authentication logs, process creation events, file integrity monitoring (FIM) events, network connection logs, and the honeypot trigger events (see 3.3).

### 3.2 Detection agents
- A small set of focused agents backed by both **trained ML models** and **deterministic rules**:
  - **Ransomware agent** — mass file renames, rapid entropy increase, shadow-copy/backup deletion commands, known ransomware-note filenames.
  - **Corruption/integrity agent** — unexpected checksum mismatches or writes to files that shouldn't change.
  - **Malicious-activity agent** — Isolation Forest for auth anomalies (impossible travel, odd-hour logins), XGBoost/Random Forest for suspicious process trees, FFT + DBSCAN for beaconing detection.
- Each agent outputs a **confidence score + supporting evidence**, which becomes raw input to the Threat Correlation Engine and Hypothesis Generation Agent rather than a final verdict in itself.
- ML models (Isolation Forest, XGBoost) are trained offline in Phase 1A and loaded at runtime.

### 3.3 Honeypot/deception layer
- **IT-side:** Custom file-based honeytokens — fake credential files, decoy documents, decoy database connection strings, VPN config bait, DNS canary tokens. Monitored via the existing Sysmon/auditd → Wazuh pipeline.
- **OT/ICS-side:** Conpot (open source ICS honeypot) for decoy Modbus/S7comm endpoints.
- **Placement strategy:** decoys concentrated near high-value or legacy/unpatched assets rather than placed randomly.
- **Output:** every interaction event is pushed into the SIEM pipeline as a special, maximum-confidence alert type.

### 3.4 Correlation & lateral-movement agent
- Builds a short-lived graph (nodes = users/hosts/processes/IPs, edges = observed interactions in a recent time window) and traverses outward from the triggering event using NetworkX 2-hop ego graphs.
- Maps the leading hypothesis's technique(s) to **MITRE ATT&CK** via a **FAISS vector DB** built from the official ATT&CK STIX dataset with embeddings generated by Gemini Flash / Sentence-BERT.

### 3.4a APT attribution + next-stage prediction
- Maps the leading hypothesis to **known threat actor TTP chains** (not just individual techniques).
- **Predicts the likely next technique** in the chain based on observed progression, giving defenders proactive warning.
- Uses the NetworkX 2-hop ego graph for lateral-movement context and outputs a confidence score for the attribution.

### 3.5 Hypothesis Generation Agent
- A **Gemini Flash** agent given the correlated evidence for an entity, with access to the **FAISS ATT&CK RAG** vector DB, asked to produce 2–4 competing hypotheses (including a benign one), each with a confidence score and the specific evidence supporting it.
- This is deliberately kept separate from the detection agents (3.2) so that raw signal-scoring and incident-level reasoning don't get conflated — the detection agents say "this looks unusual," the hypothesis agent says "here's what that unusual activity might mean."

### 3.6 Risk Scoring & Action Ranking module
- Deterministic, not LLM-driven — a small scoring function applied to a fixed action menu (isolate host, revoke credential, block IP, snapshot VM, monitor only) for the leading hypothesis.
- `α`/`β` weights should be configurable per organisation/asset criticality, since a hospital network and an exam-board database server have very different tolerance for disruption.

### 3.7 Orchestration agent (dry-run + SOAR playbook)
- Dry-run mode simulates the top-ranked action and logs the predicted effect before anything touches a real (or lab) system.
- **Autonomy rule:** confidence **≥ 0.75** AND low blast radius → auto-execute via SOAR playbook (isolate, revoke, block IP); anything broader requires human approval via the escalation gate.

### 3.8 Closed-loop outcome monitoring
- A short follow-up window after execution re-checks the relevant signals (file activity, honeypot interactions, process state) for the same entity.
- Outcome (resolved / persisted / escalated) is written back into the baseline store, adjusting future hypothesis confidence for similar evidence patterns.

### 3.9 Audit ledger
- A hash-chained append-only log (each entry includes a hash of the previous entry) recording every hypothesis set, every risk score, every dry-run prediction, every live action, and every monitored outcome.

### 3.10 SOC Dashboard (React)
- A **React SPA** frontend with a **Flask/FastAPI API backend** and real-time updates via WebSocket/SSE.
- Displays: live alert feed, TTP map visualization, MTTD/MTTR metrics, hypothesis ladder with confidence scores, honeypot confirmations, risk-ranked actions, dry-run results, executed/escalated actions, action timeline, and the full audit trail for any selected incident.

---

## 4. Datasets & data sources

| Purpose | Source |
|---|---|
| Background "normal" + labeled attack network traffic | CSE-CIC-IDS2018 |
| SOC-realistic multi-stage attack scenarios (APT, ransomware, web attacks) | Splunk BOTS (Boss of the SOC) |
| Behavioral/auth baselining | LANL Authentication dataset |
| OT/ICS attack scenarios | SWaT and WADI (iTrust, SUTD), or HAI dataset |
| MITRE ATT&CK technique/tactic data (RAG corpus) | Official MITRE ATT&CK STIX bundles |
| Vulnerability context | NVD CVE feed, CISA Known Exploited Vulnerabilities catalog |
| India-specific framing | Publicly published CERT-In advisories (manually curated, small set) |
| Honeypot interaction events | **Self-generated** — Canarytokens/Conpot logs triggered via MITRE Caldera or Atomic Red Team adversary emulation in a lab |

---

## 5. Tech stack

- **SIEM:** Wazuh + Elasticsearch
- **Honeypots:** Canarytokens (IT), Conpot (OT/ICS)
- **Attack simulation for demo:** MITRE Caldera or Atomic Red Team
- **ML models:** Isolation Forest + XGBoost/LightGBM (trained offline, loaded at runtime) via scikit-learn/xgboost/lightgbm
- **LLM agent:** Gemini Flash via `google-generativeai`
- **Knowledge base / RAG:** MITRE ATT&CK STIX data embedded into **FAISS** vector store (`faiss-cpu` + `sentence-transformers`)
- **Graph correlation:** NetworkX (prototype) with 2-hop ego graph traversal
- **Risk scoring:** plain Python/NumPy — deliberately simple and auditable, not a black box
- **Audit ledger:** hash-chained JSON log (Python `hashlib`)
- **Dashboard:** React SPA frontend + Flask/FastAPI API backend + WebSocket/SSE for real-time updates
- **Data preprocessing:** pandas, imbalanced-learn (SMOTE), scikit-learn (StandardScaler)

---

## 6. Build roadmap

1. **Lab setup** — Wazuh/ELK, a few VMs, Canarytokens + Conpot wired into the SIEM.
2. **Replay realistic traffic** — feed CSE-CIC-IDS2018/Splunk BOTS/SWaT data into the lab for "normal + attack" background noise.
3. **Detection agents v1** — ransomware/corruption/malicious-activity agents against replayed data.
4. **Honeypot integration** — confirm honeypot events flow in as maximum-confidence alerts.
5. **Hypothesis Generation Agent** — wire detection + honeypot signals into multi-hypothesis reasoning.
6. **Correlation/attribution agent** — lateral-movement graph + ATT&CK RAG mapping for the leading hypothesis.
7. **Risk Scoring module** — implement and tune the composite-score formula against a sample action menu.
8. **Orchestration agent** — dry-run simulation, blast-radius/threshold gating, at least one fully autonomous and one human-gated action.
9. **Closed-loop monitoring** — post-action re-check + baseline feedback.
10. **Audit ledger** — wire every hypothesis/score/dry-run/action/outcome into the hash-chained log.
11. **Demo run** — use Caldera/Atomic Red Team to simulate an attack that touches a honeypot and trips a detection agent; record the full pipeline (hypotheses → score → dry-run → action → outcome) reacting in real time.
12. **Dashboard polish + deck** — architecture diagram, metrics, demo video.

---

## 7. Evaluation metrics (matching the challenge's judging criteria)

- **Anomaly/ransomware detection rate** and **false-positive rate**, measured against CSE-CIC-IDS2018/Splunk BOTS benchmark traffic.
- **ATT&CK attribution accuracy** at the technique level, measured against Caldera/Atomic Red Team's known ground-truth technique IDs.
- **Hypothesis ranking accuracy** — how often the correct explanation is ranked highest among the generated hypotheses.
- **Automation coverage** — percentage of containment playbook steps that execute without human input.
- **Dry-run safety net effectiveness** — how often the dry-run stage correctly predicted a disruption that would have changed the action choice.
- **MTTD/MTTR improvement** versus a simulated "manual SOC" baseline.
- **Auditability** — every hypothesis, score, dry-run, action, and outcome traceable in the hash-chained ledger.

---

## 8. Known limitations / future work

- This is a lab-scale prototype; real deployment would need integration with actual EDR/firewall/IAM APIs rather than mocked actions.
- Honeypot placement strategy is currently heuristic — a future version could use a digital-twin/asset-graph approach to optimize decoy placement automatically.
- **Structural/graph-based feasibility validation** — checking a hypothesis against the actual privilege/network topology graph before trusting it (rather than only correlating observed interactions after the fact) — is a deliberately deferred addition for a future iteration; see the accompanying comparison document for why this is currently out of scope.
- Cross-agency threat intelligence sharing (federated, privacy-preserving) is out of scope for this prototype but is a natural extension given India's DPDP Act constraints.
- OT/ICS decoys (Conpot) only cover a subset of real-world protocols — production use would need broader protocol coverage.
- **Cloud/AWS coverage** is out of scope for this prototype — the system targets on-premise lab infrastructure. A future iteration would add cloud-native honeytokens (AWS CloudTrail canaries, fake IAM keys, S3 bucket decoys), cloud SIEM integration (AWS Security Hub, GuardDuty), and cloud-native containment actions (security group rules, IAM policy revocation).

### Possible extensions (if time permits)

Small, self-contained improvements that can be added without architectural changes:

| Extension | Enhances | What it does |
|---|---|---|
| **Signal TTL / temporal decay** | Correlation engine | Exponential decay on signal weights so old signals fade instead of accumulating — prevents stale data from inflating composite scores |
| **Baseline cold-start fallback** | BaselineStore | Pre-computed global baselines for new/unseen entities until they accumulate enough local observations; cold-start signals tagged with lower weight |
| **LLM fallback mode** | Hypothesis agent | Rule-based deterministic hypothesis generator when Gemini Flash API is unreachable — pipeline degrades gracefully instead of stalling |
| **Adaptive deception budget** | Adaptive deception | Rate-limit concurrent adaptive decoy sets (e.g., max 5 entities) to prevent environment flooding during noisy periods |
| **IOC enrichment** | Signal fusion | Check flagged IPs/hashes against AbuseIPDB and VirusTotal for confidence boost via real-world threat intel |
| **Evidence preservation** | Orchestrator | Auto-snapshot (process list, connections, recent files) before destructive containment actions to preserve forensic evidence |
| **Campaign grouping** | APT attribution | Cluster related entities (overlapping techniques + graph connectivity) into campaign chains for more accurate attribution and next-stage prediction |