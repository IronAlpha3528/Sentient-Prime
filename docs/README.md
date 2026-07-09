# Docs

**Documentation** — architecture diagrams, benchmark results, presentation materials, and project documentation.

## Structure

```
docs/
├── architecture/       # Pipeline diagrams and system design docs
├── benchmarks/         # Detection accuracy, MTTD/MTTR, attribution results
├── presentation/       # Slide deck for hackathon submission
└── README.md
```

## Planned Documents

| Document | Description |
|---|---|
| Architecture diagram | Full 17-stage pipeline: specialist ML → meta-classifier → 5 AI agents (correlation, hypothesis, prediction, deception, response) → policy gate → execution |
| Benchmark results | TP/FP rates, precision/recall/F1, ATT&CK attribution accuracy |
| Calibration table | Predicted vs. observed accuracy per confidence bucket |
| MTTD/MTTR comparison | System vs. manual SOC baseline |
| Presentation deck | Problem, architecture, novelty (Hybrid Graph-RAG, adaptive deception), benchmarks, demo |
