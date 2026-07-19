# Sentient-Prime Hackathon Readiness Audit Report

This report outlines the findings from an exhaustive, file-by-file audit of the Sentient-Prime repository. It covers cross-file logic errors, Docker configuration bugs, UI/UX gaps, and core architectural flaws that are guaranteed to cause crashes, hangs, or failures during a live hackathon demonstration.

## 1. Docker & Infrastructure Deep Dive

- **[Critical UI/UX] Missing Graph Data Volume:** `docker-compose.yml` mounts the `./data` folder to the API container but **fails to mount `./processed`**. The API relies on `processed/graph/graph.json` to serve the UI. In Docker, it will permanently fall back to a hardcoded placeholder topology, completely ruining the GraphRAG visualization demo.
- **[Critical Reliability] Webhook Crash-Loop:** `Dockerfile.webhook` is configured to run `sentinel_prime.simulation.honeypots.webhook_receiver`. However, the `honeypots` directory and file do not exist in the repository. The container will immediately crash with a `ModuleNotFoundError` on `docker-compose up`.
- **[High Performance] Docker Context Bloat (No `.dockerignore`):** The repository lacks a `.dockerignore` file. Both `Dockerfile.api` and `Dockerfile.webhook` execute a naive `COPY . .`. This copies `node_modules`, `.git`, `venv`, and large model files into the daemon context, bloating the Docker build time and causing massive system lag when preparing the demo.
- **[Medium Architecture] Redundant Dev Server:** `Dockerfile.frontend` uses `npm run dev` instead of building a static production bundle (`npm run build`). This consumes significantly more memory (Node.js watcher overhead). Furthermore, `api_server.py` is configured to serve the frontend statically, meaning there are two conflicting frontend delivery mechanisms.
- **[Medium Networking] Hardcoded Vite Proxy:** `vite.config.ts` hardcodes the API proxy to `127.0.0.1:8000`. If the Vite proxy is ever utilized inside the Docker network, it will resolve to the frontend container itself rather than the `api` service, resulting in `ECONNREFUSED` connection errors.

## 2. Frontend UI/UX & API Bridge

- **[High UX] Undefined Human Approval UI:** The architecture specifies a "Human Approval SOAR Queue". While `api_server.py` implements `/api/incidents/<id>/approve`, the React frontend (`client.ts`) **completely lacks a method to call this endpoint**. It is impossible to demo the human-in-the-loop validation through the dashboard.
- **[High UI/UX] Frontend Split-Brain:** The repository contains both a legacy Streamlit app (`dashboard/app.py`) and a React dashboard (`dashboard/frontend/`). This splits the frontend presentation and should be consolidated into one polished React interface for the pitch.

## 3. Cross-File Core & Telemetry Tracing

- **[Critical Architecture] Blocking Broadcaster Loop:** The `StreamManager.broadcast()` method synchronously loops over all subscribers (including GraphBuilder and AI Agents) in a single dispatcher thread. If an AI agent takes 60 seconds to respond, the entire stream manager freezes and drops new incoming telemetry.
- **[Critical Performance] SQLite Concurrency Deadlock:** `IncidentStateDB` inside `state_db.py` uses SQLite without enabling Write-Ahead Logging (`PRAGMA journal_mode=WAL`). During the demo, if the event bus rapidly writes incidents while the API server is reading them for the dashboard, SQLite will throw `database is locked` exceptions, crashing the backend.
- **[Critical Performance] O(E) Graph Traversal Under Global Lock:** In `verification.py`, the `_verify_loop` monitors outcomes by locking the `GraphManager` and iterating over *every single edge* in the entire graph repeatedly. This string-parsing loop holding the global lock will freeze the system over time.
- **[Medium Reliability] Missing Feature Error Handling:** Detectors like `identity_detector.py` throw raw `ValueError`s if expected JSON features are missing. These errors are not caught upstream, meaning a single malformed event sent during the demo will crash the detection pipeline.

## 4. RAG & AI Agent Context Verification

- **[Critical Reliability] Brittle AI Pipeline (No Retry):** The orchestrator in `pipeline.py` wraps calls to LLMs (`AnalysisAgent().run()`) without any retry mechanisms. If Gemini throws a 429 Rate Limit or a 502 Bad Gateway during the live pitch, the pipeline crashes ungracefully and the incident reasoning is permanently lost.
- **[High Architecture] Context Fallback Subverts GraphRAG:** In `pipeline.py`, if `framework.build_context()` fails, it silently defaults to passing raw telemetry evidence to the AI agents. This completely bypasses the graph context and ruins the LLM's ability to demonstrate GraphRAG correlation.
- **[High Performance] Threading on CPU-Bound RAG Tasks:** The RAG module (`query.py`) uses `ThreadPoolExecutor` for `SentenceTransformer` operations. Because embedding generation is purely CPU-bound, Python's Global Interpreter Lock (GIL) serializes the threads, causing severe latency spikes compared to sequential execution.
- **[Medium UX] Lazy RAG Model Cold-Start:** `query.py` lazily loads the FAISS index, HuggingFace models, and CrossEncoders *inside* the `search` function. The first time a query is executed during the demo, the API will freeze for ~10-15 seconds while models load into RAM.

## 5. SOAR Execution Chain

- **[Medium Logic] Duplicated & Conflicting Policy Gates:** `policy_gate.py` has two conflicting functions: `evaluate()` and `evaluate_policy()`. One uses a `0.75` threshold and returns `{"decision": ...}`, while the other uses `0.85` and returns `{"status": ...}`. This guarantees a downstream `KeyError` depending on which interface the orchestrator accidentally imports.

## Conclusion

The architecture of Sentient-Prime is highly ambitious, but the implementation suffers from dangerous cross-file assumptions. To ensure a successful hackathon demo, the team must address the missing Docker volumes, switch SQLite to WAL mode, decouple the synchronous Stream Manager, implement retry logic for the AI Agents, and ensure all React API routes match the backend expectations.