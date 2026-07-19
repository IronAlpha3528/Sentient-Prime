# Dashboard — SOC Dashboard

Real-time web interface for the full incident lifecycle, from raw alerts to final outcomes.
The dashboard is a **React SPA** served by the Flask API backend.

## Directory Structure

```
dashboard/
├── __init__.py
├── api_server.py            # Flask API backend (serves React SPA + REST endpoints)
├── frontend/                # React SPA (Vite + TypeScript)
│   ├── src/
│   │   ├── components/      # UI components (Topology, Incidents, AI Reasoning, etc.)
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
└── README.md
```

## Dashboard Views

| View | Description |
|---|---|
| **Alert Feed** | Live stream of detection signals and honeypot triggers (passive + adaptive) |
| **Hypothesis Ladder** | 2–4 ranked hypotheses per entity with confidence bars |
| **TTP Map** | MITRE ATT&CK matrix heatmap of observed techniques |
| **Action Timeline** | Chronological: risk scores → dry-run → execution/escalation → outcome |
| **Deception Status** | Active adaptive decoys per entity, touch/decay status |
| **MTTD/MTTR Metrics** | Detection and response time charts |
| **Audit Trail** | Hash-chained ledger entries for any selected incident |
| **Escalation Queue** | Pending actions awaiting human manual approval |

## Data Source

- Elasticsearch (SIEM events, signals)
- SQLite (honeytoken registry, baseline store)
- JSON lines (audit ledger at `data/audit_ledger.jsonl`)

## Run (Development)

Start the API backend and the React dev server separately:

```bash
# Terminal 1 — Flask API backend
python dashboard/api_server.py

# Terminal 2 — React frontend (hot-reloading)
cd dashboard/frontend
npm install
npm run dev
```

Or start both together via Docker Compose:

```bash
docker-compose up
```

The React dev server runs on `http://localhost:5173` and proxies API calls to the Flask backend on `http://localhost:8000`.
