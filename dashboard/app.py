"""Streamlit SOC dashboard backed by Sentinel-Prime's audit ledger."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sentinel_prime.core.telemetry.ledger import AuditLedger  # noqa: E402

LEDGER_PATH = PROJECT_ROOT / "data" / "audit_ledger.jsonl"
TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# ---------------------------------------------------------------------------
# Premium theme tokens
# ---------------------------------------------------------------------------
THEME = {
    "bg_from": "#0A0A0A",
    "bg_to": "#0A0A0A",
    "panel": "#181818",
    "panel_border": "rgba(212,175,55,0.18)",
    "panel_border_active": "rgba(212,175,55,0.18)",
    "text": "#FFFFFF",
    "text_muted": "#7A7A7A",
    "label": "#B5B5B5",
    "accent": "#D4AF37",
    "accent_2": "#C9A227",
    "accent_gold": "#E6C65C",
    "resolved": "#34D399",
    "escalated": "#F59E0B",
    "persisting": "#EF4444",
    "auto": "#D4AF37",
    "pending": "#7A7A7A",
}

STATUS_COLORS = {
    "RESOLVED": THEME["resolved"],
    "ESCALATED": THEME["escalated"],
    "PERSISTING": THEME["persisting"],
    "AUTO": THEME["auto"],
    "PENDING": THEME["pending"],
}


def load_ledger_entries(path: Path = LEDGER_PATH) -> list[dict[str, Any]]:
    """Read valid JSONL ledger records without modifying the audit log."""
    if not path.exists():
        raise FileNotFoundError(f"Audit ledger not found at {path}. Is the backend running?")

    entries = []
    with path.open(encoding="utf-8") as ledger_file:
        for line in ledger_file:
            if line.strip():
                entries.append(json.loads(line))
    return sorted(entries, key=lambda entry: entry.get("timestamp", ""), reverse=True)


def incident_summaries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    incidents: dict[str, dict[str, Any]] = {}
    for entry in reversed(entries):
        incident_id = entry.get("incident_id") or "UNASSIGNED"
        summary = incidents.setdefault(
            incident_id,
            {
                "incident_id": incident_id,
                "first_seen": entry.get("timestamp"),
                "last_seen": entry.get("timestamp"),
                "events": 0,
                "decision": "PENDING",
                "outcome": "PENDING",
            },
        )
        summary["last_seen"] = entry.get("timestamp")
        summary["events"] += 1
        data = entry.get("data", {})
        if entry.get("event_type") in {"policy_decision", "escalation"}:
            summary["decision"] = data.get("decision", "ESCALATE")
        if entry.get("event_type") == "monitor_outcome":
            summary["outcome"] = data.get("status", "PENDING")
    return sorted(incidents.values(), key=lambda item: item["last_seen"] or "", reverse=True)


def extract_techniques(entries: list[dict[str, Any]]) -> Counter[str]:
    return Counter(TECHNIQUE_PATTERN.findall(json.dumps(entries)))


def response_seconds(entries: list[dict[str, Any]]) -> list[float]:
    grouped: dict[str, dict[str, str]] = defaultdict(dict)
    for entry in entries:
        incident_id = entry.get("incident_id")
        if incident_id and entry.get("event_type") in {"dry_run", "monitor_outcome"}:
            grouped[incident_id][entry["event_type"]] = entry.get("timestamp", "")

    durations = []
    for timestamps in grouped.values():
        if {"dry_run", "monitor_outcome"} <= timestamps.keys():
            start = datetime.fromisoformat(timestamps["dry_run"])
            end = datetime.fromisoformat(timestamps["monitor_outcome"])
            durations.append(max((end - start).total_seconds(), 0))
    return durations


def status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status.upper(), THEME["pending"])
    return (
        f"<span class='sp-badge' style='--b:{color}'>"
        f"<span class='sp-dot'></span>{status}</span>"
    )


def _premium_css() -> str:
    return f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    #root, .stApp {{
        background: radial-gradient(1200px 600px at 80% -10%, #14233f 0%, transparent 60%),
                    radial-gradient(900px 500px at -10% 110%, #101b35 0%, transparent 55%),
                    linear-gradient(180deg, {THEME['bg_from']} 0%, {THEME['bg_to']} 100%);
        background-attachment: fixed;
        color: {THEME['text']};
        font-family: 'Inter', system-ui, sans-serif;
    }}

    /* Headings */
    .stApp h1, .stApp h2, .stApp h3 {{ font-family: 'Space Grotesk','Inter',sans-serif; }}
    .stApp h1 {{ font-weight: 700; letter-spacing: -0.01em; }}

    /* Glass panels for metric cards */
    [data-testid="stMetric"] {{
        background: {THEME['panel']};
        border: 1px solid {THEME['panel_border']};
        border-radius: 14px;
        padding: 16px 18px;
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        box-shadow: 0 8px 28px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.04);
        transition: border-color .2s ease, transform .2s ease;
    }}
    [data-testid="stMetric"]:hover {{
        border-color: {THEME['panel_border_active']};
        transform: translateY(-2px);
        box-shadow: 0 0 12px {THEME['accent']};
    }}
    [data-testid="stMetric"] label {{
        color: {THEME['text_muted']};
        font-size: 0.72rem;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        font-weight: 600;
    }}
    [data-testid="stMetric"] [data-testid="stMetricValue"] {{
        color: {THEME['text']};
        font-family: 'Space Grotesk','Inter',sans-serif;
        font-weight: 700;
        font-size: 1.55rem;
    }}

    /* Section labels */
    .section-label {{
        color: {THEME['label']};
        font-size: 0.76rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
    }}
    .section-label::before {{
        content: '';
        width: 24px; height: 2px;
        background: linear-gradient(90deg, {THEME['accent']}, {THEME['accent_2']});
        border-radius: 2px;
    }}

    /* Status badge */
    .sp-badge {{
        --b: {THEME['pending']};
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        color: var(--b);
        background: color-mix(in srgb, var(--b) 14%, transparent);
        border: 1px solid color-mix(in srgb, var(--b) 40%, transparent);
    }}
    .sp-dot {{
        width: 7px; height: 7px;
        border-radius: 50%;
        background: var(--b);
        box-shadow: 0 0 8px var(--b);
    }}

/* Header strip */
.sp-hero {{
    display:flex;
    align-items:center;
    gap:1rem;
    padding:8px 0;
    background:linear-gradient(180deg,{THEME['bg_from']} 0%,{THEME['bg_to']} 100%);
    border-radius:8px;
    box-shadow:0 4px 12px rgba(0,0,0,0.2);
}}
.sp-logo {{
    width:48px; height:48px;
    border-radius:14px;
    display:grid; place-items:center;
    font-family:'Space Grotesk',sans-serif;
    font-weight:700; font-size:1.4rem;
    color:{THEME['text']};
    background:linear-gradient(135deg,{THEME['accent']} 0%,{THEME['accent_2']} 100%);
    box-shadow:0 8px 24px rgba(107,164,255,0.35);
}}
.sp-hero h1 {{ margin:0; font-size:1.5rem; }}
.sp-hero p {{ margin:0; color:{THEME['text_muted']}; font-size:0.9rem; }}

    /* Tabs */
    .stTabs [data-baseline] {{ display: none; }}
    .stTabs [role="tab"] {{
        color: {THEME['text_muted']};
        font-weight: 600;
        font-size: 0.86rem;
        padding: 8px 14px;
        border-radius: 10px !important;
        border: none !important;
        background: transparent !important;
    }}
    .stTabs [role="tab"]:hover {{ color: {THEME['text']}; }}
    .stTabs [aria-selected="true"] {{
        color: {THEME['text']} !important;
        background: transparent !important;
        border-bottom: 2px solid {THEME['accent']};
        box-shadow: none;
    }}

    .stTabs [data-testid="stMarkdownContainer"] p {{ margin-top: 2px; }}

    /* Sidebar */
    section[data-testid="stSidebar"] {{
        background: #0D1626;
        border-right: 1px solid {THEME['panel_border']};
    }}
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {{ color: {THEME['text']}; }}
    /* Buttons */
    .stButton > button {{
        background: linear-gradient(135deg, {THEME['accent']} 0%, {THEME['accent_2']} 100%);
        color: #0a0f1d;
        border: none;
        font-weight: 700;
        letter-spacing: 0.02em;
        border-radius: 10px;
        padding: 8px 16px;
        box-shadow: 0 8px 22px rgba(107,164,255,0.28);
        transition: transform .15s ease, box-shadow .2s ease;
    }}
    .stButton > button:hover {{
        transform: translateY(-1px);
        box-shadow: 0 12px 28px rgba(107,164,255,0.4);
    }}

    /* Data frames & json */
    .stDataFrame, .stJson {{
        background: {THEME['panel']};
        border: 1px solid {THEME['panel_border']};
        border-radius: 12px;
        overflow: hidden;
        backdrop-filter: blur(10px);
    }}

    /* Divider */
    .sp-divider {{
        height: 1px;
        background: linear-gradient(90deg, transparent, {THEME['panel_border_active']}, transparent);
        margin: 6px 0 14px 0;
        border: none;
    }}

    /* Scrollbar */
    ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
    ::-webkit-scrollbar-track {{ background: transparent; }}
    ::-webkit-scrollbar-thumb {{
        background: rgba(120,160,220,0.25);
        border-radius: 10px;
    }}
    ::-webkit-scrollbar-thumb:hover {{ background: rgba(150,190,255,0.4); }}
    ..sp-status{{font-weight:700;color:#ffffff;padding:2px 6px;border-radius:4px;background-color:rgba(212,175,55,0.15);}}
.sp-timestamp{{font-size:0.8rem;color:{THEME['text_muted']};}}
.sp-btn{{background:#000000;color:{THEME['text']};border:2px solid {THEME['accent']};border-radius:8px;padding:6px 12px;transition:transform .2s,border-color .2s;}}
.sp-btn:hover{{transform:scale(1.05);border-color:{THEME['accent_2']};}}
    """


def _hero() -> None:
    """Render the premium top navigation bar."""
    from datetime import datetime
    st.markdown(
        f"""
        <div class='sp-hero'>
          <div class='sp-logo'>SP</div>
          <div class='sp-hero-title'>
            <h1>Sentinel Prime · AI SOC</h1>
          </div>
          <div class='sp-hero-actions'>
            <span class='sp-status'>🚨 LIVE</span>
            <span class='sp-timestamp'>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</span>
            <button class='sp-btn' id='refresh-btn'>⟳ Refresh</button>
            <button class='sp-btn' id='deploy-btn'>🚀 Deploy</button>
          </div>
        </div>
        <hr class='sp-divider'/>
        """,
        unsafe_allow_html=True,
    )
    # Attach actions
    if st.session_state.get('refresh'):
        st.session_state.refresh = False
        st.rerun()
    if st.session_state.get('deploy'):
        st.session_state.deploy = False
        # placeholder: future deploy logic
        st.success('Deploy triggered')
    
    # Handle button clicks via JS event listeners
    st.markdown('''
    <script>
    const refreshBtn = document.getElementById('refresh-btn');
    if(refreshBtn){refreshBtn.onclick=()=>{window.location.reload();}}
    const deployBtn = document.getElementById('deploy-btn');
    if(deployBtn){deployBtn.onclick=()=>{alert('Deploy action stub');}}
    </script>
    ''', unsafe_allow_html=True)



def render_app() -> None:
    st.set_page_config(
        page_title="Sentinel Prime SOC",
        page_icon="S",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(_premium_css(), unsafe_allow_html=True)

    entries = load_ledger_entries()
    summaries = incident_summaries(entries)
    ledger_ok = AuditLedger(LEDGER_PATH).verify_chain()
    escalations = sum(item["outcome"] == "ESCALATED" for item in summaries)
    active = sum(item["outcome"] in {"PENDING", "PERSISTING"} for item in summaries)
    durations = response_seconds(entries)

    _hero()

    # ---- Sidebar -----------------------------------------------------------
    with st.sidebar:
        st.markdown(
            f"<h3 style='margin:0'>Control Center</h3>"
            f"<p style='color:{THEME['text_muted']};margin:2px 0 14px 0;font-size:.8rem'>"
            f"Runtime oversight & ledger integrity</p>",
            unsafe_allow_html=True,
        )
        if st.button("⟳ Refresh data", use_container_width=True):
            st.rerun()
        integrity_label = "Ledger chain verified" if ledger_ok else "Ledger integrity failure"
        integrity_badge = status_badge("RESOLVED" if ledger_ok else "ESCALATED")
        st.markdown(
            f"<div style='display:flex;align-items:center;gap:.5rem;margin:.5rem 0 .25rem 0'>"
            f"{integrity_badge}<span style='color:{THEME['text_muted']};font-size:.8rem'>"
            f"{integrity_label}</span></div>",
            unsafe_allow_html=True,
        )
        st.caption(f"Ledger source: `{LEDGER_PATH.relative_to(PROJECT_ROOT)}`")

        st.markdown(
            f"<p style='color:{THEME['label']};font-size:.72rem;letter-spacing:.14em;"
            f"text-transform:uppercase;font-weight:700;margin:18px 0 6px 0'>Inspect incident</p>",
            unsafe_allow_html=True,
        )
        selected_id = st.selectbox(
            "Inspect incident",
            [item["incident_id"] for item in summaries] or ["No incidents"],
            label_visibility="collapsed",
        )
        selected_entries = [
            entry for entry in entries if entry.get("incident_id") == selected_id
        ]

    # ---- KPI strip ---------------------------------------------------------
    metrics = st.columns(5)
    mean_response = f"{sum(durations) / len(durations):.1f}s" if durations else "No data"
    kpis = [
        ("Tracked incidents", len(summaries), None),
        ("Active / persisting", active, THEME["persisting"]),
        ("Human escalations", escalations, THEME["escalated"]),
        ("Audit records", len(entries), None),
        ("Mean response", mean_response, THEME["accent_gold"]),
    ]
    for col, (label, value, tint) in zip(metrics, kpis):
        with col:
            st.metric(label, value)
            if tint:
                st.markdown(
                    f"<div style='height:3px;width:42%;border-radius:3px;"
                    f"background:{tint};opacity:.85;margin-top:-6px'></div>",
                    unsafe_allow_html=True,
                )

    if not entries:
        st.info(
            "No audit events yet. Run a SOAR dispatch or the integration tests to populate "
            "`data/audit_ledger.jsonl`; this dashboard will refresh from that real data."
        )

    (
        incident_tab,
        reasoning_tab,
        timeline_tab,
        ttp_tab,
        deception_tab,
        escalation_tab,
        audit_tab,
    ) = st.tabs(
        [
            "Incident Feed",
            "AI Reasoning",
            "Action Timeline",
            "ATT&CK Map",
            "Deception",
            "Escalation Queue",
            "Audit Trail",
        ]
    )

    def section(label: str) -> None:
        st.markdown(f"<p class='section-label'>{label}</p>", unsafe_allow_html=True)

    with incident_tab:
        section("Live incident and outcome feed")
        if summaries:
            table = pd.DataFrame(summaries)
            st.dataframe(table, use_container_width=True, hide_index=True)
        else:
            st.caption("The feed will show detector and SOAR incidents after the first dispatch.")

    with reasoning_tab:
        section("AI correlation, hypotheses, prediction and response")
        st.caption(
            "AI agent outputs appear here when they are persisted to the ledger "
            "by the runtime pipeline."
        )
        reasoning_entries = [
            entry
            for entry in selected_entries
            if entry.get("event_type")
            in {"ai_correlation", "ai_hypotheses", "ai_prediction", "ai_response"}
        ]
        if reasoning_entries:
            for entry in reasoning_entries:
                st.subheader(entry["event_type"].replace("_", " ").title())
                st.json(entry.get("data", {}))
        else:
            st.caption("No persisted AI reasoning is available for this incident yet.")

    with timeline_tab:
        section("Risk → dry-run → policy → action → outcome")
        if selected_entries:
            for entry in reversed(selected_entries):
                event_type = entry.get("event_type", "event").replace("_", " ").title()
                st.markdown(f"**{entry.get('timestamp', '')}**  |  {event_type}")
                st.json(entry.get("data", {}), expanded=False)
        else:
            st.caption("Select an incident after ledger events are available.")

    with ttp_tab:
        section("Observed MITRE ATT&CK techniques")
        techniques = extract_techniques(selected_entries or entries)
        if techniques:
            technique_frame = pd.DataFrame.from_dict(
                techniques, orient="index", columns=["observations"]
            )
            st.bar_chart(technique_frame, color=THEME["accent"])
        else:
            st.caption("No MITRE technique IDs have been persisted in the available audit records.")

    with deception_tab:
        section("Adaptive deception deployments and status")
        decoys = [entry for entry in entries if "decoy" in entry.get("event_type", "")]
        if decoys:
            st.dataframe(pd.DataFrame(decoys), use_container_width=True, hide_index=True)
        else:
            st.caption("No adaptive decoys have been deployed or recorded.")

    with escalation_tab:
        section("Incidents awaiting analyst approval")
        queued = [item for item in summaries if item["decision"] == "ESCALATE"]
        if queued:
            st.dataframe(pd.DataFrame(queued), use_container_width=True, hide_index=True)
            st.warning("Approval controls are intentionally not connected to execution yet.")
        else:
            st.caption("No incidents are currently waiting for human approval.")

    with audit_tab:
        section("Hash-chained evidence of every SOAR decision")
        integrity_status = "RESOLVED" if ledger_ok else "ESCALATED"
        st.markdown(
            f"<div style='margin:6px 0'>Integrity: {status_badge(integrity_status)}</div>",
            unsafe_allow_html=True,
        )
        if selected_entries:
            st.dataframe(pd.DataFrame(selected_entries), use_container_width=True, hide_index=True)
        else:
            st.caption("No ledger entries are available.")


if __name__ == "__main__":
    render_app()
