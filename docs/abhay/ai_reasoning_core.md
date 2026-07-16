# AI Reasoning Core

The AI Reasoning Core utilizes Google Gemini Flash via 5 logically separate and strictly constrained agents. These agents process structured JSON containing evidence and graph-RAG context, and output structured JSON to prevent hallucinations and uncontrolled actions.

## 1. Correlation Agent
**Input**: Evidence + Cyber Entity Graph features + Meta-Classifier threat score + MITRE ATT&CK context.
**Output**: A cross-domain incident story.
**Purpose**: To translate statistical correlations from ML models into a cohesive, human-readable narrative linking identity, endpoint, network, and OT signals.

## 2. Hypothesis Agent
**Input**: Incident story + raw evidence + ATT&CK context.
**Output**: 2-4 ranked hypotheses, complete with confidence levels and supporting evidence.
**Purpose**: Forces the AI to preserve a benign alternative explanation, acknowledging that not every anomaly is an attack.

## 3. Prediction Agent
**Input**: Hypotheses + ATT&CK RAG + graph + asset criticality.
**Output**: Current attack stage, predicted next stage/technique, likely target, and candidate attack paths.
**Purpose**: Provides proactive warnings to defenders about what the adversary might do next.

## 4. Deception Agent
**Input**: Uncertain hypotheses + predictions + graph topology.
**Output**: Decoy type selection, placement location, and observation window.
**Purpose**: Performs active hypothesis testing by placing honeypots to turn moderate uncertainty into high-confidence evidence.

## 5. Response Agent
**Input**: Hypotheses + predictions + ATT&CK mitigations + asset criticality + SOAR allowlist.
**Output**: Ranked containment action candidates with reasoning and expected impact.
**Purpose**: Proposes evidence-grounded containment plans without executing them. Execution is handled strictly by the Deterministic Policy Gate.
