# Phase 1 Implementation Added to the Existing Repository

This implementation deliberately follows the repository's existing module layout instead of introducing a second project structure.

## What existed before

The repository already had the architectural modules:

- `ingestion/`
- `detectors/`
- `correlation/`
- `agent/`
- `honeypots/`
- `orchestrator/`
- `risk_scoring/`
- `monitoring/`
- `ledger/`
- `dashboard/`
- `data/`

It also already contained the baseline store, honeypot webhook receiver, architecture documentation, configuration, and tests.

## What Phase 1 adds

- `detectors/evidence_schema.py` — unified specialist detector output
- `detectors/base_detector.py` — common detector interface
- `detectors/network_detector.py` — saved LightGBM runtime inference
- `ingestion/network_adapter.py` — network flow feature boundary
- `ingestion/telemetry_router.py` — telemetry type routing
- `correlation/evidence_stream.py` — JSONL AI/correlation input boundary
- `orchestrator/phase1_pipeline.py` — Phase-1 runtime coordinator
- `data/training/network_common.py`
- `data/training/inspect_network.py`
- `data/training/preprocess_network.py`
- `data/training/train_network.py`
- `data/training/evaluate_network.py`
- `data/training/aggregate_lanl.py`
- `run_phase1.py`

No existing team implementation file was deleted or overwritten except documentation/dependency metadata being extended.

## Current executable flow

```
CSE-CIC-IDS2018 CSVs
        |
        v
inspect_network.py
        |
        v
preprocess_network.py
        |
        +--> train.parquet
        +--> valid.parquet
        +--> test.parquet
        +--> metadata.json (feature contract)
        |
        v
train_network.py
        |
        +--> network_model.txt
        +--> label_encoder.pkl
        +--> feature_columns.json
        |
        v
run_phase1.py
        |
        v
Phase1Pipeline
        |
        v
TelemetryRouter
        |
        v
NetworkFlowAdapter
        |
        v
NetworkDetector
        |
        v
DetectorEvidence
        |
        v
data/runtime/evidence/events.jsonl
        |
        v
FUTURE: Cyber Entity Graph -> Meta LightGBM -> ATT&CK RAG -> AI Agents
```

## LANL flow currently added

```
lanl-auth-dataset-1-00.bz2
        |
        v
bz2 streaming reader
        |
        v
user + 1-hour window
        |
        v
auth_count / unique_computers / fanout / auth-gap features
        |
        v
lanl_user_hour_windows.parquet
```

The Isolation Forest is intentionally not trained yet. Historical novelty features such as `new_computer_ratio` must be added before freezing the identity model contract.

## Commands

Place CSE-CIC CSVs in `data/raw/cse-cic-ids2018/`.

Then:

```bash
python -m data.training.inspect_network
python -m data.training.preprocess_network
python -m data.training.train_network
python -m data.training.evaluate_network
python run_phase1.py
```

Place the compressed LANL chunk in `data/raw/lanl-auth/`.

Then:

```bash
python -m data.training.aggregate_lanl
```

## Upgrades in Phase 1 v2

Phase 1 v2 introduces crucial modeling updates to eliminate class imbalance issues in the network domain and prevent global activity thresholds from dominating the identity domain.

---

## Network Hierarchical Detection v2

### Approach Comparison

#### **Old Network Approach (v1)**
```text
Network flow
    ↓
15-class LightGBM Model
    ↓
Dataset-specific labels (imbalanced)
```
*   **Problems**: Severe class imbalance. Minor classes (e.g. SQL Injection or Infiltration) are dominated by high-volume classes (e.g. DDoS / DoS / Benign). The conditional recall of Infiltration flows was a mere **2.2%**.

#### **New Network Hierarchical Approach (v2)**
```text
Network flow
    ↓
Stage 1: Binary LightGBM (Benign vs Attack-like)
    ↓
If Attack-like: Stage 2: Multiclass LightGBM
    ↓
Attack Family Labels (Botnet, BruteForce, DDoS, DoS, Infiltration, WebAttack)
    ↓
Weak Network Evidence Object
```

### Key Upgrades and Design Decisions

1.  **Imbalance Mitigation via Hierarchical Decomposition**
    By separating the classification into a detection stage (Stage 1) and a family categorizer (Stage 2), we allow each model to optimize for a specific, simpler decision boundary. 
    *   **Stage 1** focuses on separating Benign from Attack traffic using a weighted binary objective.
    *   **Stage 2** isolates attack-only classes, balancing minority classes using training-set class counts dynamically.

2.  **Broad Attack Family Mapping**
    Mapping dataset-specific labels into broad attack families (Botnet, BruteForce, DDoS, DoS, Infiltration, WebAttack) makes the output generalized. Rather than trying to predict specialized labels unique to a specific capture environment, the model feeds high-level behavioral evidence into the future AI correlation layer.

3.  **Weak Evidence Design**
    Neither stage claims a "confirmed compromise." A positive prediction on Stage 1 maps to the classification `"network_behaviour_deviation"`. The predicted attack family is packaged under `evidence` along with Stage 1 and Stage 2 probability mappings, serving as weak signals.

---

## Identity Relative Behaviour Detection v2

### Approach Comparison

#### **Old Identity Approach (v1)**
```text
Per-user hourly windows (Absolute + Relative features)
    ↓
Isolation Forest
    ↓
Global activity levels dominate anomalies (e.g. high-volume users flagged as anomalies)
```

#### **New Identity Approach (v2)**
```text
Per-user hourly windows (Relative deviation features only)
    ↓
Isolation Forest (v2)
    ↓
True user-relative anomalies (absolute metrics kept as context only)
```

### Key Upgrades and Design Decisions

1.  **Removal of Absolute Features from the ML Contract**
    Absolute features (`auth_count`, `unique_computers`, `fanout_rate`) were removed from the Isolation Forest's feature contract. This forces the model to learn relative deviations (such as z-scores and novelty ratios) rather than absolute traffic volume. This eliminates the "U12 problem," where globally active accounts are continuously flagged as anomalies despite behaving consistently with their baseline.

2.  **Robust Z-Score Clipping**
    To prevent divisions by extremely small historical standard deviations from creating infinite or highly volatile features, we enforce `MIN_STD_EPSILON = 0.0001`. Additionally, z-scores are clipped to a bounded range `[-10.0, 10.0]`. Values beyond these bounds already represent extreme behavioral deviations; clipping ensures feature stability.

3.  **Score Normalization and Efficacy Notice**
    Isolation Forest anomaly scores are mapped to a `[0.0, 1.0]` suspiciousness score using bounds computed strictly on the training set, eliminating leakage. The output is classified conservatively as a `"behavioural_deviation"` and never treated as a confirmed threat on its own.

---

## Network v2.1 Weak Evidence Analysis

### The Hard Decision Bottleneck
Under the initial v2 implementation, a binary hard threshold of `0.50` was used to classify flows as attack or benign:
$$\text{attack\_probability} \ge 0.50 \rightarrow \text{attack}$$
$$\text{attack\_probability} < 0.50 \rightarrow \text{benign}$$

While this binary classification works well for high-volume attacks (e.g. DDoS, DoS), it serves as a bottleneck for slow, low-volume attacks such as **Infiltration**, where the Stage-1 model produces low probability scores (often below 0.50). Discarding these scores as "normal" deletes valuable weak evidence that down-stream AI correlation layers could compile with other signals (such as UEBA timing anomalies and PowerShell logs).

To preserve this signal, the v2.1 Network detector implements **evidence classification bands**:
- `attack_probability < 0.10` $\rightarrow$ `"minimal_network_evidence"`
- `0.10 <= attack_probability < 0.30` $\rightarrow$ `"weak_network_evidence"`
- `0.30 <= attack_probability < 0.50` $\rightarrow$ `"moderate_network_evidence"`
- `attack_probability >= 0.50` $\rightarrow$ `"strong_network_evidence"`

### Probability Interpretation Notice
An attack probability of `0.31` does **not** represent a $31\%$ probability of compromise. Rather, it represents the LightGBM model's estimated class probability under its training distribution. Because this score is returned alongside Stage 2 family distributions (e.g., `Infiltration` probability: `0.87`), raw probabilities are preserved in the `DetectorEvidence` for the future AI Correlation Agent to reason over without loss of information.

---

## Identity v2.1 Relative Timing and Traversal Features

### Timing Redundancy and Low-Activity Dominance
In Identity v2, `mean_auth_gap`, `min_auth_gap`, and `max_auth_gap` were passed to the Isolation Forest as absolute, raw timing features. For low-activity windows containing exactly two events:
$$\text{mean\_auth\_gap} = \text{min\_auth\_gap} = \text{max\_auth\_gap}$$
This caused a single timing interval deviation to be duplicated across three separate model dimensions. The Isolation Forest splits became dominated by these low-activity windows, causing them to receive extremely high suspiciousness scores (e.g. `0.9492` for 2 auth events) without any deterministic behavioral reason.

### User-Relative Baselines (v2.1)
In version 2.1, absolute features are removed from the ML feature contract. We introduce per-user chronological baselines for both timing and traversal rate:
1.  **`mean_auth_gap_zscore`**: The z-score of the current window's mean authentication gap calculated relative to the user's historical gaps.
2.  **`fanout_rate_zscore`**: The z-score of the current host traversal velocity relative to the user's historical rates.
3.  **`has_auth_gap`**: A binary flag (`1` if `auth_count >= 2`, `0` if `auth_count < 2`) that prevents fabricating a timing deviation for single-event windows (where no gap exists).

Raw values (`mean_auth_gap`, `fanout_rate`) are retained as metadata context for explanations, but only the user-relative z-scores enter the Isolation Forest ML feature space. This ensures the detector strictly evaluates behavioral deviation relative to each user's history, rather than absolute values or global activity levels.

