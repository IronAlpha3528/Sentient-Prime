import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any
from sentinel_prime.core.evidence.contracts import verify_evidence_contract, ContractViolationError
from sentinel_prime.core.evidence.schemas import DetectorType, EntityType
from sentinel_prime.core.evidence.severity import SeverityLevel

@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized: Dict[str, Any] = field(default_factory=dict)

def validate_evidence(evidence: Any) -> ValidationResult:
    """Validates the input evidence object against BaseEvidence rules

    and structural constraints. Returns a ValidationResult.
    """
    errors = []
    warnings = []
    normalized_dict = {}

    # 1. Contract Verification
    try:
        verify_evidence_contract(evidence)
    except ContractViolationError as e:
        errors.append(str(e))
        return ValidationResult(valid=False, errors=errors, warnings=warnings)
    except Exception as e:
        errors.append(f"Unexpected error checking contract: {e}")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)

    # 2. Check detector name
    detector = getattr(evidence, 'detector')
    if not isinstance(detector, str) or not detector.strip():
        errors.append("detector name must be a non-empty string")
    elif not DetectorType.has_value(detector):
        errors.append(f"Invalid detector '{detector}'. Supported: {[e.value for e in DetectorType]}")
    else:
        normalized_dict['detector'] = detector.upper()

    # 3. Check entity name
    entity = getattr(evidence, 'entity')
    if not isinstance(entity, str) or not entity.strip():
        errors.append("entity must be a non-empty string")
    else:
        normalized_dict['entity'] = entity.strip()

    # 4. Check entity type
    entity_type = getattr(evidence, 'entity_type')
    if not isinstance(entity_type, str) or not entity_type.strip():
        errors.append("entity_type must be a non-empty string")
    elif not EntityType.has_value(entity_type):
        errors.append(f"Invalid entity_type '{entity_type}'. Supported: {[e.value for e in EntityType]}")
    else:
        normalized_dict['entity_type'] = entity_type.upper()

    # 5. Check timestamps
    for tf in ['timestamp', 'window_start', 'window_end']:
        val = getattr(evidence, tf, None)
        if val:
            try:
                # Standardize UTC indicator 'Z' to '+00:00' for standard python compatibility
                iso_str = str(val).replace('Z', '+00:00')
                dt = datetime.datetime.fromisoformat(iso_str)
                normalized_dict[tf] = dt.isoformat()
            except Exception:
                errors.append(f"Invalid ISO format for {tf}: '{val}'")
        else:
            if tf == 'timestamp':
                errors.append("timestamp is required and cannot be empty")

    # 6. Check risk_score and confidence
    for f_name in ['risk_score', 'confidence']:
        val = getattr(evidence, f_name)
        try:
            f_val = float(val)
            if not (0.0 <= f_val <= 1.0):
                errors.append(f"{f_name} '{val}' must be in range [0.0, 1.0]")
            else:
                normalized_dict[f_name] = f_val
        except (ValueError, TypeError):
            errors.append(f"Invalid float format for {f_name}: '{val}'")

    # 7. Check severity level
    severity = getattr(evidence, 'severity')
    if not isinstance(severity, str) or not severity.strip():
        errors.append("severity must be a non-empty string")
    elif not SeverityLevel.has_value(severity):
        errors.append(f"Invalid severity '{severity}'. Supported: {[e.value for e in SeverityLevel]}")
    else:
        normalized_dict['severity'] = severity.upper()

    # 8. Check schema_version
    schema_version = getattr(evidence, 'schema_version', 'v1')
    if not isinstance(schema_version, str) or not schema_version.strip():
        errors.append("schema_version must be a non-empty string")
    else:
        normalized_dict['schema_version'] = schema_version.strip()

    # 9. Carry metadata and top reasons
    top_reasons = getattr(evidence, 'top_reasons', [])
    if not isinstance(top_reasons, list):
        errors.append("top_reasons must be a list of strings")
    else:
        normalized_dict['top_reasons'] = [str(r) for r in top_reasons]

    metadata = getattr(evidence, 'metadata', {})
    if not isinstance(metadata, dict):
        errors.append("metadata must be a dictionary")
    else:
        normalized_dict['metadata'] = metadata.copy()

    # Carry class-specific attributes
    for attr in dir(evidence):
        if (not attr.startswith('_') 
            and attr not in normalized_dict 
            and attr not in ['validate', 'to_dict', 'to_json', 'from_dict', 'from_json', 'summary', 'pretty_print']):
            val = getattr(evidence, attr)
            if not callable(val):
                normalized_dict[attr] = val

    valid = len(errors) == 0
    return ValidationResult(valid=valid, errors=errors, warnings=warnings, normalized=normalized_dict)
