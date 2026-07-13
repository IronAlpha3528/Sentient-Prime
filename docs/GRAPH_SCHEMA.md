# CKG Graph Schema Contract

This document specifies the node types, edge types, index fields, and temporal attributes of the **Cyber Knowledge Graph (CKG)** within Sentient-Prime.

---

## 1. Node Schema

Nodes represent cyber entities. Every node contains the following key-value pairs:

| Property | Type | Description |
| :--- | :--- | :--- |
| `node_id` | `str` | Prefix ID string (e.g. `HOST:10.0.0.1`, `USER:alice`). |
| `entity_type` | `str` | Entity category (e.g. `HOST`, `USER`, `PROCESS`, `PLC`). |
| `display_name`| `str` | Human-friendly name. |
| `risk_score` | `float` | Cumulative peak risk value mapped from `0.0` to `1.0`. |
| `confidence` | `float` | Cumulative peak confidence value mapped from `0.0` to `1.0`. |
| `severity` | `str` | Peak qualitative threat tier (`INFO` to `CRITICAL`). |
| `first_seen` | `str` | ISO timestamp of the earliest associated event. |
| `last_seen` | `str` | ISO timestamp of the latest associated event. |
| `metadata` | `Dict` | Merged attributes from all reporting detectors. |

---

## 2. Edge Schema

Edges represent directed relationships between nodes. Every edge carries the following attributes:

| Property | Type | Description |
| :--- | :--- | :--- |
| `type` | `str` | Relationship type (e.g. `AUTHENTICATES_TO`, `RUNS_PROCESS`). |
| `first_seen` | `str` | ISO timestamp of the earliest interaction. |
| `last_seen` | `str` | ISO timestamp of the latest interaction. |
| `occurrence_count`| `int` | Cumulative frequency count of this relation. |
| `timestamp` | `str` | Latest ISO timestamp of this relation. |
| `confidence` | `float` | Highest confidence score recorded for this relation. |
| `source_detector` | `str` | The detector that generated the relation. |
| `risk` | `float` | Highest threat risk score recorded for this relation. |
| `metadata` | `Dict` | Merged metadata attributes. |

---

## 3. Index System

The graph store maintains four optimized lookup indexes in memory:
- **Entity ID Index**: Instant direct lookup of any node by its unique string key.
- **Detector Index**: Instant listing of relationships created by `NETWORK`, `IDENTITY`, `ENDPOINT`, or `OT` modules.
- **Risk Index**: Nodes sorted by threat risk score descending, allowing instant lookup of high-threat entities.
- **Timestamp Index**: Nodes and edges sorted chronologically by update timestamp.

---

## 4. Future Compatibility

The schema allows adding new node types (such as `EMAIL`, `CONTAINER`, `VM`, `CLOUD`, `DNS`) and edge types without database schema rebuilds, as all properties are resolved as standard NetworkX MultiDiGraph attributes.
