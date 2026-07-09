# Ledger — Tamper-Evident Audit Ledger

SHA-256 hash-chained, append-only log recording every decision and action in the pipeline.

## Directory Structure

```
ledger/
├── __init__.py
├── audit_ledger.py          # append_entry() + verify_chain() implementation
├── schemas.py               # Entry type definitions (hypothesis, action, outcome, etc.)
└── README.md
```

## How It Works

Each entry includes a SHA-256 hash of the previous entry, forming an immutable chain:

```
Entry N:   { data: {...}, prev_hash: hash(Entry N-1), hash: sha256(data + prev_hash) }
Entry N+1: { data: {...}, prev_hash: hash(Entry N),   hash: sha256(data + prev_hash) }
```

Tampering with any entry breaks the chain — `verify_chain()` detects this.

## What Gets Logged

| Event | When |
|---|---|
| AI Correlation | When cross-domain incident story is generated |
| AI Hypothesis generation | After hypothesis agent run (2-4 hypotheses + confidence scores) |
| AI Attack prediction | After prediction agent estimates next stage/target |
| AI Response planning | After response agent proposes containment candidates |
| Risk score | After deterministic action ranking |
| Dry-run prediction | Before live execution |
| Action execution | When SOAR playbook fires |
| Action escalation | When human gate is triggered |
| Adaptive decoy deployment | When moderate-score entity triggers deception |
| Adaptive decoy cleanup | When TTL expires or entity confirmed |
| Outcome monitoring | After follow-up window (resolved/persisted/escalated) |

## Storage

Output: `data/audit_ledger.jsonl` — one JSON object per line, append-only.
