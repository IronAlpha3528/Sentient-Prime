# Sentinel-Prime — Build TODO List (Agent-Ready)

Project: Agentic AI Cyber Resilience platform — SIEM log analysis + honeypot deception layer (passive + adaptive) + multi-hypothesis reasoning + risk-weighted containment + dry-run execution + closed-loop monitoring + audit ledger.

Goal: a working lab-scale prototype demonstrating the full two-phase pipeline end-to-end, benchmarked against open datasets and self-generated adversary-emulation data, packaged with an architecture diagram, a demo video, and a presentation deck.

Architecture: **Phase 1 (offline)** trains ML models + builds FAISS vector DB → **Phase 2 (online)** runs the 10-stage runtime pipeline with adaptive deception and closed-loop feedback.

Each task below includes: what to build, how to build it, and a concrete "done" condition. Work top to bottom within a phase; phases can overlap once their dependencies are met (noted inline).

---

## PHASE 0 — Environment & Repo Setup

- [ ] **0.1 Initialize repo structure**
  Create the following directories: `ingestion/`, `honeypots/`, `detectors/`, `agent/`, `correlation/`, `risk_scoring/`, `orchestrator/`, `monitoring/`, `ledger/`, `dashboard/`, `attack_sim/`, `data/`, `tests/`, `docs/`.
  Done when: repo skeleton exists with a placeholder `README.md` in each subfolder describing its purpose.

- [ ] **0.2 Provision lab VMs**
  Set up: 1 SIEM server (Wazuh manager + Elasticsearch + Kibana), 2-3 "production" VMs (Windows/Linux) with Sysmon/auditd + Wazuh agent installed, 1 attacker VM (Caldera or Atomic Red Team installed), 1 lightweight VM/container for OT/ICS honeypot (Conpot).
  Done when: all VMs can ping each other, Wazuh manager dashboard is reachable, and at least one agent is reporting into it.

- [ ] **0.3 Set up Python environment**
  Create a virtualenv/poetry project with: `elasticsearch`, `networkx`, `pandas`, `numpy`, `google-generativeai` (Gemini Flash), `flask`, `flask-cors`, `flask-socketio`, `pyyaml`, `requests`, `scikit-learn`, `xgboost`, `lightgbm`, `faiss-cpu`, `sentence-transformers`, `imbalanced-learn` (SMOTE), `pySigma`, `pymodbus`, `python-dotenv`.
  Done when: a `requirements.txt`/`pyproject.toml` is committed and `pip install -r requirements.txt` runs clean.

- [ ] **0.4 Download datasets**
  Pull CSE-CIC-IDS2018, Splunk BOTS (Boss of the SOC v2/v3), LANL Authentication dataset, SWaT (or HAI as fallback), and the official MITRE ATT&CK STIX bundle (Enterprise + ICS matrices) into `data/raw/`.
  Done when: all datasets are present locally and a short script confirms row counts and column schemas for each. Note: CSE-CIC-IDS2018 has ~7.5% label noise — Splunk BOTS (human-verified ground truth) is the primary benchmark.

---

## PHASE 1 — Telemetry & Honeypot Layer (no dependency on Phase 1A/2+)

- [ ] **1.1 Configure Sysmon/auditd on production VMs**
  Use SwiftOnSecurity's Sysmon config for process creation, file create/delete, network connection events. For Linux VMs, enable auditd rules covering file writes and process execs.
  Done when: events from both VM types appear in the Wazuh/Elasticsearch index within seconds of being generated.

- [ ] **1.2 Deploy Canarytokens (IT-side passive honeypots)**
  Generate fake credential files, decoy Word/PDF docs with embedded web beacons, decoy database connection strings, and DNS canary tokens. Place them in realistic locations (decoy creds in a fake config file, decoy doc in a shared drive, VPN config in a user profile, etc.) across the production VMs.
  Done when: triggering each token manually fires a webhook, and that webhook payload is captured.

- [ ] **1.3 Pipe Canarytokens webhooks into the SIEM**
  Write a Flask receiver that accepts Canarytoken webhook POSTs, normalizes them into JSON with `event_type: honeypot`, and forwards into Elasticsearch. Also handle Conpot events with `event_type: honeypot_ot`.
  Done when: a manual honeypot trigger shows up in Kibana tagged `event_type: honeypot` within a few seconds.

- [ ] **1.4 Deploy Conpot (OT/ICS honeypot)**
  Stand up Conpot with a default or lightly customized template (generic ICS/Modbus profile). Confirm it logs interactions.
  Done when: a manual Modbus probe (using `pymodbus`) generates a log entry forwarded into the SIEM tagged `event_type: honeypot_ot`.

- [ ] **1.5 Baseline store**
  Build a SQLite-backed `BaselineStore` class with `update(entity_id, metric, value)` and `deviation(entity_id, metric, value)` methods, computing rolling mean/std per entity per metric using Welford's online algorithm.
  Done when: feeding a few days of replayed benign traffic produces sensible per-entity baselines (spot-check a few entities manually). Unit tests pass.

---

## PHASE 1A — Offline Training Pipeline (depends on 0.4, can run in parallel with Phase 1)

- [ ] **1A.1 Data preprocessing**
  Build `data/preprocessing.py`: load CSE-CIC-IDS2018 and Splunk BOTS raw data, drop nulls, encode categoricals (label/one-hot), apply SMOTE for class imbalance, feature scaling (StandardScaler), train/test split (80/20 stratified).
  Done when: preprocessed train/test splits are saved to `data/processed/` and a short script confirms balanced class distributions and expected feature dimensions.

- [ ] **1A.2 Train Isolation Forest (unsupervised anomaly scorer)**
  Fit an Isolation Forest on normal-only traffic from CSE-CIC-IDS2018 and LANL Auth data. Serialize the trained model to `data/models/isolation_forest.pkl`.
  Done when: the model correctly assigns high anomaly scores to labeled attack samples and low scores to benign samples from a held-out test set.

- [ ] **1A.3 Train XGBoost classifier (supervised attack classifier)**
  Train an XGBoost/LightGBM classifier on labeled CSE-CIC-IDS2018 + Splunk BOTS data for multi-class attack type classification. Serialize to `data/models/xgboost_classifier.json`.
  Done when: the classifier achieves ≥95% accuracy on the CSE-CIC-IDS2018 test set (noting the ~7.5% label noise caveat) and sensible precision/recall on BOTS data.

- [ ] **1A.4 Build FAISS vector DB for ATT&CK TTPs**
  Parse the official ATT&CK STIX bundle (Enterprise + ICS matrices). Embed technique/tactic descriptions using Gemini Flash embeddings or `sentence-transformers` (`all-MiniLM-L6-v2`). Index into a FAISS vector store. Serialize to `data/models/attack_faiss.index`.
  Done when: querying "mass file encryption + shadow copy deletion" returns T1486 and T1490 as the top matches.

- [ ] **1A.5 Compile Sigma rules + threshold configs**
  Source or write Sigma rules for deterministic patterns (shadow copy deletion, encoded PowerShell, ransomware-note filenames, LOLBin chains). Configure entropy thresholds and z-score baseline parameters. Save to `detectors/sigma_rules/` and `data/models/baseline_thresholds.json`.
  Done when: all rule sets and threshold configs are versioned and loadable by the runtime pipeline.

---

## PHASE 2 — Detection Agents (depends on 1.1, 1.5, 1A.2, 1A.3, 1A.5)

- [ ] **2.1 Sigma rule detector**
  Load compiled Sigma rules from 1A.5. Wire `pySigma` to match against incoming SIEM events for: shadow copy/backup deletion commands, encoded/obfuscated PowerShell execution, known ransomware-note filename patterns, suspicious LOLBin process chains (Office → cmd → powershell).
  Done when: correctly fires on at least 5 distinct known-malicious log samples and does not fire on a benign control set.

- [ ] **2.2 File entropy detector**
  Implement Shannon entropy calculation on file content before/after modification (via FIM hooks or periodic sampling). Flag files crossing the configurable entropy threshold from 1A.5 (e.g., jump from <6 to >7.5 bits/byte).
  Done when: correctly separates plaintext vs. AES-encrypted versions of the same test files.

- [ ] **2.3 Mass file-activity detector**
  Implement a write-rate anomaly check using the `BaselineStore`: flag when an entity's file create/modify/rename rate in a time window deviates significantly (>3 standard deviations) from that entity's own baseline.
  Done when: replaying a simulated ransomware burst (many file renames in seconds) correctly triggers a flag, and normal traffic does not.

- [ ] **2.4 Corruption/integrity agent**
  Implement FIM-based hash comparison (SHA-256) for a defined set of "should rarely change" files (configs, binaries, sample database records). Flag unexpected hash changes and tag with the identity of the writing process/user.
  Done when: a manual unauthorized edit to a watched file is detected and correctly attributed to the writer.

- [ ] **2.5 Malicious-activity agent (auth + process + network anomalies)**
  Load trained Isolation Forest (1A.2) and XGBoost (1A.3) models. Implement three sub-detectors:
  **(a)** Impossible-travel / odd-hour login detection from auth logs using Isolation Forest.
  **(b)** Suspicious process-lineage detection (Office → shell → network) using XGBoost/Random Forest.
  **(c)** Beaconing detection using FFT periodicity analysis + DBSCAN clustering on connection intervals from netflow data.
  Done when: each sub-detector correctly flags at least one labeled attack sample from CSE-CIC-IDS2018/Splunk BOTS and does not flag benign traffic from the same dataset.

- [ ] **2.6 Unified signal schema**
  Standardize every detector's output into: `{entity, signal_type, confidence, evidence, timestamp}`. Write all signals to a shared `signals` index in Elasticsearch (or a local table for prototype speed).
  Done when: running the full detector suite against a day of replayed mixed traffic produces a clean, queryable signal log.

---

## PHASE 3 — Correlation & Reasoning Layer (depends on Phase 2 output + 1.3/1.4 + 1A.4)

- [ ] **3.1 Build the correlation graph**
  Implement a `networkx`-based graph builder that ingests recent SIEM events (auth, process, network) into nodes (users/hosts/processes/IPs) and edges (interactions), with a sliding time window. Support 2-hop `ego_graph` queries.
  Done when: querying a 2-hop ego graph around a known-compromised test entity correctly surfaces the other systems it interacted with in a staged lateral-movement scenario.

- [ ] **3.2 Build the Threat Correlation Engine**
  Build the signal fusion layer that merges:
  - Anomaly scores (Isolation Forest)
  - Attack class predictions (XGBoost)
  - ATT&CK TTP matches (FAISS RAG query)
  - Co-occurrence analysis (multiple signals for the same entity in a time window)
  - Honeypot trigger flags (passive honeypot events → max confidence boost)
  Output: a **composite anomaly score** per entity per time window.
  Done when: feeding a set of raw detector signals produces enriched alerts with merged scores, and honeypot-confirmed entities have visibly higher composite scores than log-only detections.

- [ ] **3.3 Implement adaptive deception trigger**
  When the Threat Correlation Engine outputs a **moderate composite anomaly score (0.4–0.74)** for an entity:
  **(a)** Dynamically generate and deploy fresh Canarytokens in the entity's active paths — decoy credentials on systems they've accessed, breadcrumb files in directories they're browsing, DNS canaries in config files on accessed hosts.
  **(b)** Monitor for any adaptive decoy interaction within a configurable time window.
  **(c)** If the entity touches an adaptive decoy → inject a `honeypot_adaptive` event with max confidence back into the correlation engine → entity proceeds to hypothesis generation.
  **(d)** If the entity ignores all adaptive decoys for the window duration → score decays back toward baseline, adaptive decoys are cleaned up, entity classified as probably benign.
  Done when: a staged moderate-suspicion entity that subsequently accesses an adaptive decoy gets correctly boosted to max confidence and proceeds through the full pipeline. A benign entity in the same score range correctly decays and does not trigger containment.

- [ ] **3.4 Build agent tools**
  Implement callable tools for the Hypothesis Generation Agent:
  - `get_entity_baseline(entity_id)` → queries BaselineStore
  - `query_attack_technique(description)` → queries FAISS ATT&CK vector DB
  - `check_honeypot_interactions(entity_id, window)` → checks passive + adaptive decoy events
  - `get_recent_neighbors(entity_id, window)` → queries NetworkX ego graph
  Done when: each tool function works standalone against test data and returns well-formed JSON.

- [ ] **3.5 Implement the Hypothesis Generation Agent**
  Write the system prompt and orchestration code for **Gemini Flash** that:
  - Takes enriched alerts from the Threat Correlation Engine for an entity
  - Calls the FAISS ATT&CK RAG + agent tools (3.4)
  - Returns 2–4 ranked hypotheses (including a benign explanation)
  - Each hypothesis includes: confidence score, supporting evidence, suggested ATT&CK technique(s)
  Done when: feeding a known-ransomware signal cluster produces a top hypothesis matching the correct ATT&CK techniques with confidence >0.7, and a benign control case produces a top hypothesis correctly favoring the benign explanation.

- [ ] **3.6 Implement APT attribution + next-stage prediction**
  Build a component that takes the leading hypothesis and:
  **(a)** Maps it to known threat actor TTP chains using the FAISS ATT&CK vector DB.
  **(b)** Predicts the likely next technique in the chain based on observed progression.
  **(c)** Uses a NetworkX 2-hop ego graph (3.1) for lateral-movement context.
  **(d)** Outputs a confidence score for the attribution.
  Done when: feeding a multi-technique attack scenario correctly identifies the TTP chain pattern and predicts a plausible next technique matching the known attack sequence.

- [ ] **3.7 Calibration check**
  Run the agent against ~30-50 labeled incidents (mix of dataset-derived and Caldera-derived). Bucket hypotheses by confidence score and compare to actual accuracy in each bucket. Apply Platt scaling / isotonic regression for confidence recalibration.
  Done when: a calibration table exists in `docs/` showing predicted vs. observed accuracy per confidence bucket.

---

## PHASE 4 — Risk Scoring, Orchestration, Monitoring (depends on Phase 3)

- [ ] **4.1 Implement the risk scoring module**
  Build the fixed action menu (isolate host, revoke credential, block IP, snapshot VM, monitor only) with per-action containment-effectiveness and business-impact estimates. Implement:
  ```
  Composite Score = α × Containment Effectiveness − β × Business Impact
  ```
  α/β weights should be configurable per organization/asset criticality.
  Done when: running the scorer against the top hypothesis from 3.5 produces a sensible ranked action list, and changing α/β visibly shifts the ranking in the expected direction.

- [ ] **4.2 Implement dry-run simulation**
  For each action type, implement a "predict effect" function (e.g., for isolate-host: look up what services/sessions are running on that host and would be disrupted). Log the prediction to the audit ledger. Even a lookup-table-based estimate of dependencies is enough for the prototype.
  Done when: staging a test case where isolating a host would disrupt a known shared service correctly produces a dry-run warning before any live action.

- [ ] **4.3 Implement the orchestration dispatcher (SOAR playbook)**
  Build the policy gate:
  ```
  IF dry_run.passes AND confidence ≥ 0.75 AND blast_radius ≤ max_auto:
      → auto-execute via SOAR playbook (isolate, revoke, block IP)
  ELSE:
      → escalate to human-approval queue (surfaced in React dashboard)
  ```
  Wire at least 2 real/mocked actions (e.g., isolate via `iptables` / Windows Firewall rule, revoke credential via `Disable-ADAccount` or a mocked equivalent).
  Done when: a staged high-confidence (≥0.75), low-blast-radius incident triggers full autonomous execution end-to-end, and a staged broader-impact or lower-confidence incident correctly stops at the human-approval queue.

- [ ] **4.4 Implement closed-loop outcome monitoring**
  After an action executes, re-run the relevant detectors against the same entity over a short follow-up window. Classify outcome and route accordingly:
  - **Resolved** → close incident, update baselines in `BaselineStore`, recalibrate confidence weights, clean up any adaptive decoys.
  - **Persisted** → re-enter the detection pipeline (Stage 3) with same priority, try alternative containment action.
  - **Escalated** → re-enter the Threat Correlation Engine (Stage 4) with **elevated priority**, broader blast radius allowed.
  Done when: re-running the same staged attack scenario a second time (after a successful first containment) shows measurably faster/higher-confidence detection than the first run. A persisted-outcome correctly triggers re-entry into the pipeline.

---

## PHASE 5 — Audit Ledger & SOC Dashboard (can start in parallel with Phase 3/4)

- [ ] **5.1 Implement the hash-chained audit ledger**
  Build `append_entry(prev_hash, entry) -> new_hash` using SHA-256 over canonicalized JSON; persist to an append-only file or table. Write an entry at every: hypothesis generation, risk score, dry-run prediction, action execution, action escalation, adaptive decoy deployment/cleanup, and monitored outcome.
  Done when: a verification script can replay the entire ledger and confirm every hash chain link is intact, and deliberately tampering with one entry causes verification to fail.

- [ ] **5.2 Build the SOC dashboard**
  Build a **React SPA** frontend with a **Flask/FastAPI API backend** and real-time updates via WebSocket/SSE. Dashboard views:
  - **Live alert feed** — incoming detection signals and honeypot triggers (passive + adaptive)
  - **TTP map** — MITRE ATT&CK matrix heatmap of observed techniques
  - **Hypothesis ladder** — 2–4 ranked hypotheses per entity with confidence bars
  - **Action timeline** — chronological view: risk scores → dry-run → execution/escalation → outcome
  - **Adaptive deception status** — which entities have active adaptive decoys, touch/decay status
  - **MTTD/MTTR metrics** — detection and response time charts
  - **Audit trail** — hash-chained ledger entries for any selected incident
  - **Human escalation queue** — pending actions awaiting manual approval
  Done when: selecting any test incident in the dashboard shows its full lifecycle from raw signal to final outcome, including adaptive deception status and feedback loop re-entries.

---

## PHASE 6 — Benchmarking

- [ ] **6.1 Detection accuracy benchmark**
  Run the full detector suite against labeled Splunk BOTS (primary, human-verified) and CSE-CIC-IDS2018 (secondary, with label-noise caveat) samples. Compute TP rate, FP rate, precision/recall/F1, separately for:
  - Log-only detections
  - Passive honeypot-confirmed incidents
  - Adaptive deception-confirmed incidents
  Done when: a results table/notebook exists in `docs/benchmarks/`.

- [ ] **6.2 ATT&CK attribution benchmark**
  Run Caldera/Atomic Red Team scenarios with known ground-truth technique IDs through the full pipeline. Compute technique-level and tactic-level attribution accuracy. Separately evaluate next-stage prediction accuracy.
  Done when: a results table exists comparing predicted vs. ground-truth techniques, including next-stage prediction hit rate.

- [ ] **6.3 MTTD/MTTR benchmark**
  Time the full pipeline (signal ingestion → final action) against several staged incidents. Separately measure:
  - Direct high-confidence path (no adaptive deception)
  - Adaptive deception path (moderate → decoy confirmation → containment)
  Manually time a "human baseline" triage of the same raw logs for comparison.
  Done when: a comparison table/chart of system MTTD/MTTR vs. manual baseline exists, broken down by path.

- [ ] **6.4 Automation coverage & dry-run effectiveness**
  Across all benchmark runs, compute:
  - Percentage of actions executed autonomously vs. escalated to human
  - Percentage of dry-runs that correctly flagged a disruption risk in staged "trap" scenarios
  - Adaptive deception confirmation rate (how often moderate-score entities that touch decoys were truly malicious)
  Done when: all three metrics are documented with example cases.

---

## PHASE 7 — Packaging & Submission

- [ ] **7.1 Architecture diagram**
  Produce a clean, presentation-ready version of the two-phase pipeline diagram showing all 10 runtime stages, the adaptive deception branch, and the three feedback loops.

- [ ] **7.2 Presentation deck**
  Cover: problem statement, two-phase architecture, what's novel (adaptive deception on moderate scores + multi-hypothesis reasoning + next-stage prediction + dry-run safety + closed-loop learning), benchmark results, and related-work positioning vs. AgentSOC.

- [ ] **7.3 Demo video**
  Script and record a single coherent run: Caldera/Atomic Red Team triggers an attack → passive honeypot fires → adaptive deception deploys on a second moderate-suspicion entity → adaptive decoy touched → confirmed → hypotheses generate → APT attribution predicts next technique → risk scoring ranks actions → dry-run runs → autonomous action executes → outcome monitoring confirms resolution → audit ledger verified live on camera.

- [ ] **7.4 Final README pass**
  Update the README with final benchmark numbers, the adaptive deception feature, and a "how to run the demo" section.

---

# Timeline

Assuming a **7-day build window** (compress proportionally if your hackathon is shorter — see compressed version below).

| Day | Focus | Tasks |
|---|---|---|
| **Day 1** | Environment, telemetry, offline training (start) | 0.1–0.4, 1.1–1.4, 1A.1–1A.2 |
| **Day 2** | Offline training (finish) + baselines + detection agents (core) | 1A.3–1A.5, 1.5, 2.1–2.3 |
| **Day 3** | Detection agents (remaining) + signal schema | 2.4–2.6 |
| **Day 4** | Correlation engine, adaptive deception, hypothesis agent | 3.1–3.5 |
| **Day 5** | APT attribution + risk scoring + orchestration + monitoring | 3.6–3.7, 4.1–4.4 |
| **Day 6** | Audit ledger, React dashboard, benchmarking | 5.1–5.2, 6.1–6.4 |
| **Day 7** | Packaging | 7.1–7.4 |

### Compressed 3-day version (typical hackathon)

| Day | Focus | Tasks (cut scope as needed) |
|---|---|---|
| **Day 1** | Telemetry + honeypots + offline training + ONE detection agent (ransomware) | 0.1–0.4, 1.1–1.4, 1A.1–1A.4, 2.1–2.3 (skip 2.4/2.5 if tight) |
| **Day 2** | Correlation + adaptive deception + hypothesis agent + risk scoring + orchestration | 3.1–3.5 (skip 3.7 calibration), 4.1–4.3, 5.1 |
| **Day 3** | End-to-end demo run, minimal React dashboard, deck, video | 3.6 (simplified), 4.4 (simplified), 5.2 (minimal), 6.3 only (MTTD/MTTR), 7.1–7.4 |

### Priority order if you run out of time

Cut from the bottom up:
1. Calibration analysis (3.7) — nice-to-have polish
2. Next-stage prediction depth (3.6 partial) — can degrade to simple technique lookup
3. Full dashboard polish (5.2) — minimal version is fine for demo
4. Corruption/malicious-activity agents beyond ransomware (2.4/2.5)
5. Closed-loop monitoring depth (4.4) — can simplify to a basic re-check
6. OT/ICS honeypot (1.4) — IT-side Canarytokens are sufficient for demo

**Never cut:**
- **FAISS ATT&CK vector DB** (1A.4) — core to the reasoning layer
- **Adaptive deception** (3.3) — this is your most novel feature, biggest differentiator
- **Honeypot-to-SIEM-to-alert path** (1.2–1.3) — cheapest, most reliable demo
- **Audit ledger** (5.1) — cheap to build, high credibility payoff

---

# Optional Extensions (if time permits)

These are small, self-contained improvements that can be added on top of the core architecture without structural changes. Each one is independent — pick whichever fits the remaining time.

### EXT-1: Signal TTL / temporal decay (enhances 3.2)
Add exponential decay to signal weights in the Threat Correlation Engine so older signals fade instead of accumulating indefinitely:
```
effective_weight = base_weight × e^(−λ × age_minutes)
```
**Why:** Prevents stale signals from 4 hours ago polluting the composite score. Configurable `λ` controls how fast signals age out.
**Effort:** ~10 lines in the correlator.

### EXT-2: Baseline cold-start fallback (enhances 1.5 / 1A.1)
Pre-compute global fallback baselines (population-level mean/std per metric) from CSE-CIC-IDS2018 training data during Phase 1A. New or rarely-seen entities use these global baselines until they have enough local observations (e.g., ≥10). Tag cold-start signals with `baseline_maturity: cold` so the correlation engine can weight them lower.
**Why:** Without this, new entities have no reference point — z-scores are unreliable or undefined during warm-up.
**Effort:** One extra method in BaselineStore + a config step in preprocessing.

### EXT-3: LLM fallback / degraded mode (enhances 3.5)
Add a rule-based fallback hypothesis generator that activates when Gemini Flash API is unreachable or slow. Uses the FAISS ATT&CK match + signal types to produce a single deterministic hypothesis (no competing explanations). Logs degraded-mode activation to the audit ledger.
**Why:** Prevents the entire reasoning pipeline from stalling on API issues.
**Effort:** One fallback function in `hypothesis_agent.py`.

### EXT-4: Adaptive deception rate limiting (enhances 3.3)
Add a configurable **decoy budget** — maximum number of concurrently active adaptive decoy sets (e.g., max 5 entities at a time). When the budget is full, new moderate-score entities queue by composite score until a slot opens via decay or confirmation.
**Why:** Without this, a noisy period could flood the environment with hundreds of decoys, creating cleanup mess and potentially tipping off a sophisticated attacker.
**Effort:** A counter + priority queue in the adaptive deception module.

### EXT-5: IOC enrichment via AbuseIPDB / VirusTotal (enhances 2.6)
Add a lightweight enrichment step before signal fusion: check flagged IPs against AbuseIPDB (free: 1000/day) and file hashes against VirusTotal (free: 4/min). Matching IOCs get an `ioc_enrichment` field and a confidence boost.
**Why:** Nearly free to add, and showing real-world threat intel integration impresses judges. A flagged IP that's already in AbuseIPDB with a 95% reputation score is a much stronger signal.
**Effort:** One small module (`detectors/ioc_enrichment.py`) + 2 API keys in `.env`.

### EXT-6: Evidence preservation before containment (enhances 4.2 / 4.3)
Add an auto-snapshot step before any destructive action (isolate, revoke, block): capture running process list, open network connections, and recent file changes. Store alongside the action entry in the audit ledger. Non-blocking — the action proceeds immediately after snapshot starts.
**Why:** If the system isolates a host, forensic evidence (memory, processes, connections) might be lost. Best practice is to preserve before containment.
**Effort:** One function in the dry-run/orchestrator module.

### EXT-7: Multi-entity campaign grouping (enhances 3.6)
After hypothesis generation, if multiple entities share overlapping ATT&CK techniques and are connected within 2 hops in the NetworkX graph, group them into a campaign cluster. APT attribution (3.6) then reasons over the full campaign chain instead of individual entities.
**Why:** APT campaigns span multiple hosts. Attribution on a 3-entity campaign chain is far more accurate than 3 individual attributions, and next-stage prediction improves dramatically when the system sees the full progression.
**Effort:** A grouping function using NetworkX connected components — infrastructure already exists from task 3.1.