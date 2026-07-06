# Agent — Hypothesis Generation Agent

**Gemini Flash**-powered reasoning agent that produces 2–4 competing hypotheses per incident, using FAISS ATT&CK RAG for technique attribution.

## Directory Structure

```
agent/
├── __init__.py
├── hypothesis_agent.py      # Gemini Flash system prompt + orchestration
├── tools.py                 # Callable tools for structured data retrieval
├── prompts.py               # System prompt templates
└── README.md
```

## Tools

| Tool | What it queries |
|---|---|
| `get_entity_baseline(entity_id)` | BaselineStore — rolling mean/std for entity |
| `query_attack_technique(description)` | FAISS ATT&CK vector DB — top-k technique matches |
| `check_honeypot_interactions(entity_id, window)` | Honeytoken registry — passive + adaptive events |
| `get_recent_neighbors(entity_id, window)` | NetworkX ego graph — 2-hop lateral-movement context |

## Hypothesis Output Schema

```json
{
  "entity_id": "user@host",
  "hypotheses": [
    {
      "id": "H1",
      "description": "Ransomware staging (mass file modification + shadow-copy deletion)",
      "confidence": 0.78,
      "attack_techniques": ["T1486", "T1490"],
      "evidence": ["signal_id_1", "signal_id_2"],
      "is_benign": false
    }
  ],
  "timestamp": "ISO-8601"
}
```