# Tests

Unit and integration tests for all Sentinel-Prime pipeline components.

## Structure

```
tests/
├── test_baseline_store.py       # ✅ BaselineStore unit tests (21 tests passing)
├── test_webhook_receiver.py     # Webhook receiver tests
├── test_honeytoken_registry.py  # Honeytoken registry + detector tests
├── test_detectors.py            # Detection agent tests
├── test_correlator.py           # Threat correlation engine tests
├── test_hypothesis_agent.py     # Hypothesis agent tests
├── test_risk_scoring.py         # Risk scoring formula tests
├── test_audit_ledger.py         # Hash-chain integrity tests
├── test_adaptive_engine.py      # Adaptive deception lifecycle tests
├── conftest.py                  # Shared fixtures
└── README.md
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_baseline_store.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```
