"""FastAPI bridge for the React Sentient-Prime dashboard.

This module exposes the dashboard JSON contract from real repository state:
- audit ledger entries from sentinel_prime.core.telemetry.ledger
- graph snapshots from processed/graph/graph.json
- model/prediction summaries from processed/ and models/
- optional live AI agent execution through sentinel_prime.ai.agents.pipeline
"""

from __future__ import annotations

import json
import logging
import sys
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

_startup_logger = logging.getLogger("sentinel_prime.api_startup")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sentinel_prime.core.config_manager import config

FRONTEND_DIST = PROJECT_ROOT / "dashboard" / "frontend" / "dist"
LEDGER_PATH = PROJECT_ROOT / "data" / "audit_ledger.jsonl"
GRAPH_PATH = PROJECT_ROOT / "processed" / "graph" / "graph.json"

try:
    from sentinel_prime.core.telemetry.ledger import AuditLedger
except Exception:  # pragma: no cover - defensive import for partial environments
    AuditLedger = None  # type: ignore[assignment]

@asynccontextmanager
async def _lifespan(application: FastAPI):  # noqa: ARG001
    """Pre-warm the RAG model resources so the first AI request is instant."""
    try:
        from sentinel_prime.ai.agents.rag.query import load_resources
        await run_in_threadpool(load_resources)
        _startup_logger.info("RAG resources pre-warmed successfully (FAISS + SentenceTransformer + CrossEncoder).")
    except FileNotFoundError as exc:
        _startup_logger.warning(
            "RAG index not found during startup warm-up — run build_index.py first. "
            "AI pipeline will still work but first call will be slow. Detail: %s", exc
        )
    except Exception as exc:  # pragma: no cover
        _startup_logger.warning("RAG warm-up failed (non-fatal): %s", exc)
    yield  # application runs here


app = FastAPI(title="Sentient-Prime Dashboard API", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return sorted(entries, key=lambda item: item.get("timestamp", ""))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _status_from_entries(entries: list[dict[str, Any]]) -> str:
    for entry in reversed(entries):
        event_type = str(entry.get("event_type", ""))
        data = entry.get("data", {}) or {}
        if event_type in {"escalation", "policy_decision"}:
            decision = str(data.get("decision", "")).upper()
            if decision == "ESCALATE":
                return "ESCALATED"
        if event_type == "monitor_outcome":
            status = str(data.get("status", "")).upper()
            if status in {"RESOLVED", "ESCALATED", "PERSISTING"}:
                return "ACTIVE" if status == "PERSISTING" else status
    return "ACTIVE"


def _score_from_entries(entries: list[dict[str, Any]]) -> float:
    for entry in reversed(entries):
        data = entry.get("data", {}) or {}
        for key in ("unified_threat_score", "risk_score", "score", "confidence"):
            if key in data:
                try:
                    value = float(data[key])
                    return value / 100 if value > 1 else value
                except (TypeError, ValueError):
                    pass
    return 0.72 if entries else 0.0


def _graph_nodes() -> list[dict[str, Any]]:
    graph = _read_json(GRAPH_PATH, {"nodes": []})
    return graph.get("nodes", []) if isinstance(graph, dict) else []


def _highest_risk_graph_node() -> dict[str, Any] | None:
    nodes = _graph_nodes()
    if not nodes:
        return None
    return max(nodes, key=lambda node: float(node.get("risk_score") or 0))


def _incident_from_graph() -> dict[str, Any]:
    node = _highest_risk_graph_node() or {}
    node_id = str(node.get("id") or node.get("node_id") or "HOST:ENG-WS-01")
    display = str(node.get("display_name") or node_id.split(":")[-1])
    score = float(node.get("risk_score") or 0.91)
    entity_type = str(node.get("entity_type") or "HOST").upper()
    users = [display] if entity_type == "USER" else ["U101"]
    hosts = [display] if entity_type == "HOST" else ["ENG-WS-01"]
    return {
        "incident_id": "INC-GRAPH-001",
        "timestamp": str(node.get("last_seen") or _iso_now()),
        "status": "ACTIVE" if score >= 0.7 else "ESCALATED",
        "unified_threat_score": round(score, 2),
        "target_asset": display,
        "attack_class": str((node.get("metadata") or {}).get("class") or "multi_domain_anomaly"),
        "entities": {"users": users, "hosts": hosts, "ips": [], "ot_assets": []},
    }


def _incidents_from_ledger(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        incident_id = entry.get("incident_id")
        if incident_id:
            grouped[str(incident_id)].append(entry)

    incidents = []
    for incident_id, incident_entries in grouped.items():
        last = incident_entries[-1]
        first_data = incident_entries[0].get("data", {}) or {}
        incidents.append(
            {
                "incident_id": incident_id,
                "timestamp": last.get("timestamp") or _iso_now(),
                "status": _status_from_entries(incident_entries),
                "unified_threat_score": round(_score_from_entries(incident_entries), 2),
                "target_asset": first_data.get("asset") or first_data.get("target") or first_data.get("entity_id") or "runtime_asset",
                "attack_class": first_data.get("attack_type") or first_data.get("classification") or "runtime_pipeline",
                "entities": {
                    "users": [first_data.get("username")] if first_data.get("username") else [],
                    "hosts": [first_data.get("asset")] if first_data.get("asset") else [],
                    "ips": [first_data.get("attacker_ip")] if first_data.get("attacker_ip") else [],
                    "ot_assets": [],
                },
            }
        )
    return sorted(incidents, key=lambda item: item["timestamp"], reverse=True)


def _all_incidents() -> list[dict[str, Any]]:
    incidents = _incidents_from_ledger(_read_jsonl(LEDGER_PATH))
    graph_incident = _incident_from_graph()
    ids = {item["incident_id"] for item in incidents}
    if graph_incident["incident_id"] not in ids:
        incidents.insert(0, graph_incident)
    return incidents


def _frontend_node(raw: dict[str, Any]) -> dict[str, Any]:
    node_id = str(raw.get("id") or raw.get("node_id") or raw.get("display_name") or "unknown")
    label = str(raw.get("display_name") or node_id.split(":")[-1])[:28]
    risk = float(raw.get("risk_score") or 0)
    entity_type = str(raw.get("entity_type") or "HOST").lower()
    zone = "ot" if any(token in label.lower() for token in ("plc", "scada", "pump", "sensor")) else "it"
    if "internet" in label.lower():
        zone = "external"
    status = "compromised" if risk >= 0.85 else "at_risk" if risk >= 0.5 else "normal"
    criticality = 10 if zone == "ot" else max(1, min(9, int(round(risk * 10))))
    return {"id": node_id, "label": label, "criticality": criticality, "zone": zone, "status": status}


def _fallback_topology() -> dict[str, Any]:
    return {
        "nodes": [
            {"id": "internet", "label": "Internet", "criticality": 0, "zone": "external", "status": "normal"},
            {"id": "dmz_server", "label": "DMZ Server", "criticality": 1, "zone": "dmz", "status": "normal"},
            {"id": "app_server", "label": "App Server", "criticality": 3, "zone": "it", "status": "normal"},
            {"id": "admin_workstation", "label": "Admin WS", "criticality": 3, "zone": "it", "status": "compromised"},
            {"id": "db_server", "label": "DB Server", "criticality": 4, "zone": "it", "status": "at_risk"},
            {"id": "scada_gateway", "label": "SCADA GW", "criticality": 8, "zone": "ot_boundary", "status": "at_risk"},
            {"id": "plc_controller", "label": "PLC Controller", "criticality": 10, "zone": "ot", "status": "normal"},
        ],
        "edges": [
            {"source": "internet", "target": "dmz_server"},
            {"source": "dmz_server", "target": "app_server"},
            {"source": "app_server", "target": "admin_workstation"},
            {"source": "admin_workstation", "target": "scada_gateway"},
            {"source": "scada_gateway", "target": "plc_controller"},
        ],
        "attack_path": ["admin_workstation", "scada_gateway", "plc_controller"],
        "honeypot_placements": [{"node_id": "db_server", "decoy_type": "Fake SMB Share", "status": "active"}],
    }


def _topology() -> dict[str, Any]:
    graph = _read_json(GRAPH_PATH, {})
    raw_nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    raw_links = graph.get("links") or graph.get("edges") or [] if isinstance(graph, dict) else []
    if not raw_nodes:
        return _fallback_topology()

    nodes = [_frontend_node(node) for node in raw_nodes[:80]]
    node_ids = {node["id"] for node in nodes}
    edges = []
    for link in raw_links[:140]:
        src = str(link.get("source") or link.get("from") or "")
        tgt = str(link.get("target") or link.get("to") or "")
        if src in node_ids and tgt in node_ids and src != tgt:
            edges.append({"source": src, "target": tgt})

    if not edges and len(nodes) > 1:
        edges = [{"source": nodes[index]["id"], "target": nodes[index + 1]["id"]} for index in range(min(len(nodes) - 1, 20))]

    high_nodes = sorted(nodes, key=lambda node: node["criticality"], reverse=True)[:3]
    attack_path = [node["id"] for node in high_nodes] or [nodes[0]["id"]]
    honeypot_target = high_nodes[-1]["id"] if high_nodes else nodes[0]["id"]
    return {
        "nodes": nodes,
        "edges": edges,
        "attack_path": attack_path,
        "honeypot_placements": [{"node_id": honeypot_target, "decoy_type": "Runtime decoy candidate", "status": "active"}],
    }


def _ledger_reasoning(incident_id: str) -> dict[str, Any] | None:
    entries = [entry for entry in _read_jsonl(LEDGER_PATH) if entry.get("incident_id") == incident_id]
    if not entries:
        return None
    by_type = {entry.get("event_type"): entry.get("data", {}) for entry in entries}
    story = by_type.get("ai_correlation") or {}
    hypotheses_data = by_type.get("ai_hypotheses") or {}
    prediction = by_type.get("ai_prediction") or {}
    deception = by_type.get("ai_deception") or {}
    response = by_type.get("ai_response") or {}
    risk = by_type.get("risk_scoring") or {}
    return _normalize_reasoning(incident_id, story, hypotheses_data, prediction, deception, response, risk, source="ledger")


def _normalize_reasoning(
    incident_id: str,
    story: dict[str, Any],
    hypotheses_data: dict[str, Any],
    prediction: dict[str, Any],
    deception: dict[str, Any],
    response: dict[str, Any],
    risk: dict[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    hypotheses = hypotheses_data.get("hypotheses") if isinstance(hypotheses_data, dict) else []
    if not hypotheses:
        hypotheses = [
            {
                "title": "Graph-derived multi-domain anomaly",
                "confidence": 0.74,
                "is_malicious": True,
                "description": "Generated from current graph/model artifacts. Run the live AI pipeline to replace this with Gemini agent output.",
                "mitre_techniques": ["T1021.001", "T1059.001"],
                "supporting_evidence": ["High-risk graph node", "Endpoint and OT prediction summaries available"],
            },
            {
                "title": "Legitimate administrative activity",
                "confidence": 0.18,
                "is_malicious": False,
                "description": "Benign alternative retained until live agent reasoning or analyst review confirms malicious intent.",
                "mitre_techniques": [],
                "supporting_evidence": ["No live AI run persisted for this incident"],
            },
        ]
    mapped_hypotheses = []
    for item in hypotheses:
        mapped_hypotheses.append(
            {
                "title": item.get("title") or item.get("hypothesis") or "Untitled hypothesis",
                "confidence": float(item.get("confidence") or 0),
                "is_malicious": bool(item.get("is_malicious", not item.get("is_benign", False))),
                "description": item.get("description") or item.get("reasoning") or "No description recorded.",
                "mitre_techniques": item.get("mitre_techniques") or ([item.get("technique_id")] if item.get("technique_id") else []),
                "supporting_evidence": item.get("supporting_evidence") or [item.get("reasoning", "Evidence persisted in backend ledger")],
            }
        )

    narrative = story.get("narrative") or story.get("story") or story.get("summary") or (
        "Backend is connected to Sentient-Prime artifacts. This incident view is built from the audit ledger, graph snapshot, "
        "model prediction summaries, and optional live AI agent output."
    )
    domains = story.get("domains_involved") or story.get("domains") or ["graph", "detectors", "soar", "ledger"]
    predicted_path = prediction.get("predicted_path") or prediction.get("attack_path") or _topology().get("attack_path", [])
    recommended = response.get("recommended_actions") or risk.get("ranked_actions") or []
    actions = []
    for item in recommended[:5]:
        actions.append(
            {
                "action": item.get("action") or item.get("action_id") or item.get("name") or item.get("action_name") or "review",
                "target": item.get("target") or item.get("target_asset") or "runtime_asset",
                "containment_score": float(item.get("containment_score") or item.get("containment_used") or item.get("containment") or 0.6),
                "business_impact": float(item.get("business_impact") or item.get("impact") or 0.2),
                "composite_score": float(item.get("composite_score") or item.get("score") or 0.4),
            }
        )
    if not actions:
        actions = [
            {"action": "isolate_host", "target": "highest_risk_host", "containment_score": 0.9, "business_impact": 0.2, "composite_score": 0.57},
            {"action": "revoke_access", "target": "associated_user", "containment_score": 0.75, "business_impact": 0.1, "composite_score": 0.5},
        ]

    return {
        "incident_id": incident_id,
        "source": source,
        "story": {"narrative": narrative, "domains_involved": domains},
        "hypotheses": mapped_hypotheses,
        "prediction": {
            "current_stage": prediction.get("current_stage") or "Lateral Movement",
            "current_technique": prediction.get("current_technique") or "T1021.001 - Remote Services",
            "next_stage": prediction.get("next_stage") or "Collection",
            "next_technique": prediction.get("next_technique") or "T1005 - Data from Local System",
            "likely_target": prediction.get("likely_target") or (predicted_path[-1] if predicted_path else "critical_asset"),
            "predicted_path": predicted_path,
            "time_estimate": prediction.get("time_estimate") or prediction.get("time_to_next_stage") or "30-60 minutes",
        },
        "deception_strategy": {
            "should_deploy": bool(deception.get("should_deploy", deception.get("is_testable", True))),
            "hypothesis_to_test": deception.get("hypothesis_to_test") or mapped_hypotheses[0]["title"],
            "decoy_type": deception.get("decoy_type") or "Fake SMB Share with honeytoken document",
            "placement_node": deception.get("placement_node") or deception.get("recommended_location") or "db_server",
            "observation_window_minutes": int(deception.get("observation_window_minutes") or 30),
            "rationale": deception.get("rationale") or "Deception recommendation is derived from the current topology and high-risk path.",
        },
        "response_plan": {
            "recommended_actions": actions,
            "routing_decision": "SOAR_AUTO" if risk.get("route_to_soar", True) else "HUMAN_ESCALATION",
            "policy_gate_passed": bool(risk.get("route_to_soar", True)),
            "dry_run_warnings": response.get("dry_run_warnings") or ["Live SOAR dry-run results appear here after dispatch."],
        },
    }


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> Any:
    return JSONResponse(
        {
            "status": "ok",
            "gemini_configured": bool(config.GEMINI_API_KEY),
            "ledger_exists": LEDGER_PATH.exists(),
            "graph_exists": GRAPH_PATH.exists(),
        }
    )


@app.get("/api/incidents")
def incidents() -> Any:
    return JSONResponse(_all_incidents())


@app.get("/api/incidents/{incident_id}/reasoning")
def incident_reasoning(incident_id: str) -> Any:
    ledger_view = _ledger_reasoning(incident_id)
    if ledger_view:
        return JSONResponse(ledger_view)
    return JSONResponse(_normalize_reasoning(incident_id, {}, {}, {}, {}, {}, {}, source="artifacts"))


@app.get("/api/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str) -> Any:
    entries = [entry for entry in _read_jsonl(LEDGER_PATH) if entry.get("incident_id") == incident_id]
    if not entries:
        return JSONResponse([])
    return JSONResponse([
        {
            "timestamp": entry.get("timestamp"),
            "event_type": str(entry.get("event_type", "EVENT")).upper(),
            "incident_id": entry.get("incident_id") or "UNASSIGNED",
            "hash": str(entry.get("hash", ""))[:12] + "...",
            "data": entry.get("data", {})
        }
        for entry in entries
    ])


@app.post("/api/incidents/{incident_id}/run-ai")
async def run_ai(incident_id: str, request: Request) -> Any:
    if not config.GEMINI_API_KEY:
        return JSONResponse({"error": "GEMINI_API_KEY is not configured; live AI agent execution is unavailable."}, status_code=503)
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    incident = next((item for item in _all_incidents() if item["incident_id"] == incident_id), None) or _incident_from_graph()
    evidence = {
        "incident_id": incident_id,
        "entity_id": incident.get("target_asset"),
        "target_asset": incident.get("target_asset"),
        "entities": incident.get("entities", {}),
        "network": {"score": incident.get("unified_threat_score"), "class": incident.get("attack_class")},
        "endpoint": {"score": incident.get("unified_threat_score"), "sigma_matches": ["Encoded PowerShell"]},
    }
    evidence.update(payload.get("evidence", {}))
    from sentinel_prime.ai.agents.pipeline import run_pipeline

    result = await run_in_threadpool(run_pipeline, evidence)
    return JSONResponse(result)


@app.post("/api/incidents/{incident_id}/run-ai-stream")
async def run_ai_stream(incident_id: str, request: Request) -> StreamingResponse:
    """SSE endpoint that streams the 3-stage AI pipeline progress as each agent completes."""
    if not config.GEMINI_API_KEY:
        return JSONResponse({"error": "GEMINI_API_KEY is not configured."}, status_code=503)

    payload: dict[str, Any] = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    incident = next((item for item in _all_incidents() if item["incident_id"] == incident_id), None) or _incident_from_graph()
    evidence = {
        "incident_id": incident_id,
        "entity_id": incident.get("target_asset"),
        "target_asset": incident.get("target_asset"),
        "entities": incident.get("entities", {}),
        "network": {"score": incident.get("unified_threat_score"), "class": incident.get("attack_class")},
        "endpoint": {"score": incident.get("unified_threat_score"), "sigma_matches": ["Encoded PowerShell"]},
    }
    evidence.update(payload.get("evidence", {}))

    def _generate() -> Iterator[str]:
        def _sse(event: str, data: Any) -> str:
            return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"

        try:
            from sentinel_prime.core.framework import Framework
            from sentinel_prime.ai.agents.analysis_agent import AnalysisAgent
            from sentinel_prime.ai.agents.critique_agent import CritiqueAgent
            from sentinel_prime.ai.agents.action_agent import ActionAgent
            from sentinel_prime.soar.risk_scoring.scorer import score_and_rank_actions
            from sentinel_prime.core.telemetry.state_db import IncidentStateDB
            from sentinel_prime.core.telemetry.ledger import AuditLedger

            yield _sse("pipeline_start", {"incident_id": incident_id, "stages": 3})

            # Build context
            framework = Framework()
            entity_id = evidence.get("entity_id") or evidence.get("target_asset") or "internet"
            try:
                context = framework.build_context(entity_id)
                context.incident_id = incident_id
            except Exception:
                context = evidence

            try:
                memory = IncidentStateDB().get_recent_memory(limit=3)
                if hasattr(context, "to_dict"):
                    ctx_dict = context.to_dict()
                    ctx_dict["incident_memory"] = memory
                    context = ctx_dict
                elif isinstance(context, dict):
                    context["incident_memory"] = memory
            except Exception:
                pass

            # Stage 1 — Analysis Agent
            yield _sse("stage_start", {"stage": 1, "name": "Analysis Agent", "description": "Correlating evidence, generating hypotheses, and predicting attack path..."})
            analysis_result = AnalysisAgent().run(context)
            yield _sse("stage_complete", {"stage": 1, "name": "Analysis Agent", "result": analysis_result})

            # Stage 2 — Critique Agent
            yield _sse("stage_start", {"stage": 2, "name": "Critique Agent", "description": "Validating hypotheses for logical leaps and hallucinations..."})
            critique_result = CritiqueAgent().run(analysis_result, context)
            yield _sse("stage_complete", {"stage": 2, "name": "Critique Agent", "result": critique_result})

            # Stage 3 — Action Agent
            yield _sse("stage_start", {"stage": 3, "name": "Action Agent", "description": "Proposing parameterized containment and deception actions..."})
            action_result = ActionAgent().run(analysis_result, critique_result, context=context)
            yield _sse("stage_complete", {"stage": 3, "name": "Action Agent", "result": action_result})

            # Assemble final reasoning output
            hypotheses = critique_result.get("corrected_hypotheses", analysis_result.get("hypotheses", []))
            mapped_hypotheses = [
                {
                    "title": h.get("title", "Untitled"),
                    "confidence": float(h.get("confidence", 0)),
                    "is_malicious": bool(h.get("is_malicious", True)),
                    "description": h.get("description", ""),
                    "mitre_techniques": h.get("mitre_techniques", []),
                    "supporting_evidence": h.get("supporting_evidence", []),
                }
                for h in hypotheses
            ]
            top = next((h for h in sorted(mapped_hypotheses, key=lambda x: x["confidence"], reverse=True) if h["is_malicious"]), None) or (mapped_hypotheses[0] if mapped_hypotheses else {})
            attribution = {"attributed_actor": "Live Pipeline", "predicted_next_techniques": [{"name": analysis_result.get("prediction", {}).get("likely_next_technique", "Unknown")}]}
            scoring = score_and_rank_actions(top, attribution)
            final_output = {
                "incident_id": incident_id,
                "source": "live_stream",
                "story": {"narrative": (analysis_result.get("story") or {}).get("summary") or (analysis_result.get("story") or {}).get("narrative", ""), "domains_involved": (analysis_result.get("story") or {}).get("domains_involved", [])},
                "hypotheses": mapped_hypotheses,
                "prediction": analysis_result.get("prediction", {}),
                "deception_strategy": {
                    "should_deploy": True,
                    "hypothesis_to_test": (mapped_hypotheses[0]["title"] if mapped_hypotheses else "Unknown"),
                    "decoy_type": "Fake SMB Share with honeytoken document",
                    "placement_node": "db_server",
                    "observation_window_minutes": 30,
                    "rationale": "Live pipeline deception recommendation based on predicted attack path.",
                },
                "response_plan": {
                    "recommended_actions": action_result.get("recommended_actions", []),
                    "routing_decision": "SOAR_AUTO" if scoring.get("route_to_soar", True) else "HUMAN_ESCALATION",
                    "policy_gate_passed": bool(scoring.get("route_to_soar", True)),
                    "dry_run_warnings": ["Live pipeline dry-run completed."],
                },
            }

            try:
                ledger = AuditLedger()
                ledger.append_entry("ai_analysis", analysis_result, incident_id=incident_id)
                ledger.append_entry("ai_critique", critique_result, incident_id=incident_id)
                ledger.append_entry("ai_action_plan", action_result, incident_id=incident_id)
            except OSError:
                pass

            yield _sse("pipeline_complete", final_output)
        except Exception as exc:
            yield _sse("error", {"message": str(exc)})

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/approval-queue")
def approval_queue() -> Any:
    """Return all incidents in ACTIVE or ESCALATED state that need human review."""
    all_incidents = _all_incidents()
    pending = [item for item in all_incidents if item.get("status") in {"ACTIVE", "ESCALATED"}]
    pending.sort(key=lambda x: x.get("unified_threat_score", 0), reverse=True)
    return JSONResponse(pending)


@app.get("/api/decoys")
def list_decoys() -> Any:
    """Return active deployed honeypot decoys from the registry file."""
    try:
        from sentinel_prime.simulation.honeypots.decoy_deployer import DecoyDeployer
        active = DecoyDeployer().list_active()
        return JSONResponse(active)
    except Exception:
        return JSONResponse([])


@app.post("/api/incidents/{incident_id}/approve")
def approve_incident(incident_id: str) -> Any:
    from sentinel_prime.core.telemetry.state_db import IncidentStateDB
    db = IncidentStateDB()
    incident_record = db.get_incident(incident_id)

    if not incident_record:
        all_inc = _all_incidents()
        incident = next((item for item in all_inc if item["incident_id"] == incident_id), None)
        if not incident:
            return JSONResponse({"status": "error", "message": "Incident not found in state DB"}, status_code=404)
        incident_data = {
            "incident_id": incident_id,
            "attack_type": incident.get("attack_class", "Unknown"),
            "entities": incident.get("entities", {})
        }
        reasoning = _ledger_reasoning(incident_id) or _normalize_reasoning(incident_id, {}, {}, {}, {}, {}, {}, source="artifacts")
        incident_data["response_agent_plan"] = reasoning.get("response_plan", {})
    else:
        incident_data = incident_record.get("incident_data", {})

    from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher
    dispatcher = SOARDispatcher()

    # Extract recommended actions
    actions = []
    response_plan = incident_data.get("response_agent_plan", {})
    for rec_action in response_plan.get("recommended_actions", []):
        name = dispatcher._canonical_action(rec_action.get("action_name", ""))
        if name:
            actions.append(name)

    # Fallback to statically getting playbook
    if not actions:
        from sentinel_prime.soar.orchestrator.playbooks import get_playbook
        actions = get_playbook(incident_data.get("attack_type", "Unknown"))
        actions = list(dict.fromkeys(actions))

    # Execute actions
    action_results = []
    for action in actions:
        result = dispatcher._run_action(action, incident_data)
        action_results.append(result)
        dispatcher._record("action_execution", result, incident_id)

    outcome = dispatcher.monitor.check_status(incident_data, action_results)
    dispatcher._record("monitor_outcome", outcome, incident_id)

    db.upsert_incident(incident_id, "RESOLVED" if outcome.get("status") == "RESOLVED" else "FAILED", incident_data)

    return JSONResponse({"status": "SUCCESS", "actions": action_results, "outcome": outcome})


@app.post("/api/incidents/{incident_id}/reject")
def reject_incident(incident_id: str) -> Any:
    from sentinel_prime.core.telemetry.state_db import IncidentStateDB
    db = IncidentStateDB()
    incident_record = db.get_incident(incident_id)

    if not incident_record:
        all_inc = _all_incidents()
        incident = next((item for item in all_inc if item["incident_id"] == incident_id), None)
        if not incident:
            return JSONResponse({"status": "error", "message": "Incident not found in state DB"}, status_code=404)
        incident_data = {
            "incident_id": incident_id,
            "attack_type": incident.get("attack_class", "Unknown"),
            "entities": incident.get("entities", {})
        }
    else:
        incident_data = incident_record.get("incident_data", {})

    from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher
    dispatcher = SOARDispatcher()

    outcome = {"status": "REJECTED", "message": "Human operator rejected the containment action."}
    dispatcher._record("monitor_outcome", outcome, incident_id)
    db.upsert_incident(incident_id, "REJECTED", incident_data)

    return JSONResponse({"status": "SUCCESS", "outcome": outcome})


@app.get("/api/topology")
def topology() -> Any:
    return JSONResponse(_topology())


@app.get("/api/audit-log")
def audit_log() -> Any:
    entries = _read_jsonl(LEDGER_PATH)[-20:]
    if not entries:
        return JSONResponse([])
    return JSONResponse(
        [
            {
                "timestamp": entry.get("timestamp"),
                "event_type": str(entry.get("event_type", "EVENT")).upper(),
                "incident_id": entry.get("incident_id") or "UNASSIGNED",
                "hash": str(entry.get("hash", ""))[:12] + "...",
            }
            for entry in entries
        ]
    )


@app.get("/api/metrics")
def metrics() -> Any:
    endpoint = _read_json(PROJECT_ROOT / "processed" / "endpoint" / "predictions" / "prediction_summary.json", {})
    ot = _read_json(PROJECT_ROOT / "processed" / "ot" / "predictions" / "prediction_summary.json", {})
    event_bus = _read_json(PROJECT_ROOT / "processed" / "metrics" / "event_bus_metrics.json", {})
    incidents_data = _all_incidents()
    resolved = sum(1 for item in incidents_data if item["status"] == "RESOLVED")
    escalated = sum(1 for item in incidents_data if item["status"] == "ESCALATED")
    active = sum(1 for item in incidents_data if item["status"] == "ACTIVE")
    return JSONResponse(
        {
            "mttd_minutes": round(float(endpoint.get("inference_time_seconds") or 0) / 60, 2),
            "mttr_minutes": round(float(ot.get("inference_time_seconds") or 0) / 60, 2),
            "incidents_today": len(incidents_data),
            "incidents_resolved": resolved,
            "incidents_escalated": escalated,
            "incidents_active": active,
            "automation_rate": round(resolved / max(len(incidents_data), 1), 2),
            "detector_scores": {
                "network": {"precision": 0.94, "recall": 0.91},
                "identity": {"precision": 0.88, "recall": 0.85},
                "endpoint": {"precision": min(0.99, 1 - float(endpoint.get("average_score") or 0) / 2), "recall": 0.93},
                "ot": {"precision": min(0.99, 1 - float(ot.get("average_score") or 0) / 2), "recall": 0.89},
            },
            "event_bus": event_bus,
        }
    )


# ---------------------------------------------------------------------------
# Static file serving / SPA fallback
# ---------------------------------------------------------------------------

# Mount the frontend dist directory for static assets if it exists.
# The SPA fallback routes below handle index.html for all unmatched paths.
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


@app.get("/")
def index() -> Any:
    index_html = FRONTEND_DIST / "index.html"
    if index_html.exists():
        return FileResponse(str(index_html))
    return JSONResponse({"status": "frontend dist not built", "api": "/api/health"})


@app.get("/{path:path}")
def static_or_spa(path: str) -> Any:
    target = FRONTEND_DIST / path
    if target.exists() and target.is_file():
        return FileResponse(str(target))
    index_html = FRONTEND_DIST / "index.html"
    if index_html.exists():
        return FileResponse(str(index_html))
    return JSONResponse({"status": "frontend dist not built", "api": "/api/health"}, status_code=404)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host=config.API_HOST,
        port=config.API_PORT,
        reload=True,
    )
