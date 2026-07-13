# Cyber Knowledge Graph (CKG) Documentation

This document describes the structure, indices, updates, and querying mechanisms for the **Cyber Knowledge Graph (CKG)** in Sentient-Prime. The CKG maintains a semantic map of entities and relationships observed across threat specialists.

---

## Topological Schema

### Node Types
Supported node categories:
- `HOST`: Workstations, servers, domain controllers.
- `USER`: Active Directory or local user identities.
- `PROCESS`: Executed process binaries and commands.
- `DEVICE`: General networked hardware.
- `PLC`: Programmable Logic Controllers.
- `SENSOR`: Temperature, flow, or pressure sensors.
- `ACTUATOR`: Valvles, motors, pumps, or control elements.
- `NETWORK_FLOW`: Aggregated network flow records.
- `DOMAIN`: DNS domain names.
- `FILE`: Local endpoint binary or text files.
- `REGISTRY`: Windows registry keys/values.
- `SERVICE`: Local daemon or Windows services.

### Edge Types (Relationships)
Edges represent directed interactions between node entities:
- `AUTHENTICATES_TO`: A user logging into a host server.
- `RUNS_PROCESS`: A host executing a process.
- `CONNECTS_TO`: Source host initiating connection to destination host.
- `SPAWNS`: Parent process spawning child process.
- `READS` / `WRITES` / `MODIFIES`: File and registry interactions.
- `CONTROLS` / `MEASURES`: PLC and sensor/actuator relationships.
- `ACCESSES` / `QUERIES` / `USES` / `GENERATES`: General telemetry links.
- `OBSERVED_IN` / `DETECTED_BY`: Specialist mapping relationships.

---

## Indexing Subsystem

To enable sub-millisecond retrieval, `GraphStore` maintains four indices:

1. **Entity Index**: Implicit NetworkX hash map resolving node IDs directly.
2. **Timestamp Index**: Chronologically sorted list of when nodes/edges were updated.
3. **Detector Index**: Maps source detectors to relationship edges.
4. **Risk Index**: Sorted list of node risk scores.

---

## Merging & Deduplication

- **Nodes**: If a node exists, UEF keeps the oldest `first_seen` timestamp, updates the `last_seen` timestamp, records peak `risk_score` and `confidence`, takes the highest `severity` tier, and merges the metadata dictionary.
- **Edges**: If an edge exists, UEF updates `last_seen`, increments `occurrence_count`, records peak risk/confidence, and merges metadata.

---

## Validation Rules

The Graph Manager validates the graph integrity regularly to ensure:
- **No Orphan Edges**: Every edge source and target node must exist in the nodes set.
- **Invalid Types**: Nodes and edges must match defined enums.
- **Temporal Integrity**: ISO timestamps must be valid.
