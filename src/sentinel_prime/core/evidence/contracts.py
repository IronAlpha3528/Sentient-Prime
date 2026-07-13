from typing import Any

class ContractViolationError(ValueError):
    """Raised when an evidence object violates the BaseEvidence contract."""
    pass

def verify_evidence_contract(evidence: Any) -> None:
    """Enforces the BaseEvidence contract on any evidence object,

    raising ContractViolationError if violated.
    """
    required = ["detector", "entity", "timestamp", "risk_score", "confidence", "severity"]
    for field in required:
        if not hasattr(evidence, field) or getattr(evidence, field) is None or getattr(evidence, field) == "":
            raise ContractViolationError(f"Contract Violation: Missing required field '{field}'")
