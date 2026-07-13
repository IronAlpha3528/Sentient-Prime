# BaseEvidence Schema Contract

This document specifies the fields, allowed values, validation rules, and versioning constraints for the `BaseEvidence` schema. All specialized security specialist models MUST adhere to this contract.

---

## Fields and Specifications

### 1. `schema_version`
- **Type**: `str`
- **Allowed Values**: `"v1"`, `"v2"`, etc.
- **Description**: Schema schema version identifier. Current version is `"v1"`.
- **Validation Rule**: Must be a non-empty string.

### 2. `detector`
- **Type**: `str` / `DetectorType` (Enum)
- **Allowed Values**: `NETWORK`, `IDENTITY`, `ENDPOINT`, `OT`, `CLOUD`, `EMAIL`, `DNS`.
- **Description**: The specialist detector that generated the telemetry findings.
- **Validation Rule**: Case-insensitive match against allowed enums. Normalized to uppercase.

### 3. `entity`
- **Type**: `str`
- **Allowed Values**: Any unique identifier (e.g. hostnames, IP addresses, username, process ID).
- **Description**: The primary asset or actor subject to analysis.
- **Validation Rule**: Must be a non-empty string.

### 4. `entity_type`
- **Type**: `str` / `EntityType` (Enum)
- **Allowed Values**: `HOST`, `USER`, `PROCESS`, `DEVICE`, `PLC`, `SENSOR`, `ACTUATOR`, `NETWORK_FLOW`, `DOMAIN`, `FILE`, `REGISTRY`, `SERVICE`.
- **Description**: The category classification of the analyzed entity.
- **Validation Rule**: Case-insensitive match against allowed enums. Normalized to uppercase.

### 5. `timestamp`
- **Type**: `str` (ISO 8601)
- **Description**: Time when the threat/event was observed.
- **Validation Rule**: Must be a parseable ISO 8601 string. Normalized to standard UTC format.

### 6. `window_start` / `window_end`
- **Type**: `str` (ISO 8601)
- **Description**: Temporal boundaries of the window of events aggregated by the detector.
- **Validation Rule**: Optional, but if present must be parseable ISO 8601 strings.

### 7. `confidence`
- **Type**: `float`
- **Allowed Values**: `0.0` to `1.0` inclusive.
- **Description**: Specialist's confidence in its prediction/analysis accuracy.
- **Validation Rule**: Must be a float within range `[0.0, 1.0]`.

### 8. `risk_score`
- **Type**: `float`
- **Allowed Values**: `0.0` to `1.0` inclusive.
- **Description**: Estimated threat danger score. `0.0` represents benign baseline, `1.0` represents extreme risk.
- **Validation Rule**: Must be a float within range `[0.0, 1.0]`.

### 9. `severity`
- **Type**: `str` / `SeverityLevel` (Enum)
- **Allowed Values**: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Description**: Qualitative severity assessment of the threat finding.
- **Validation Rule**: Case-insensitive match against allowed enums. Normalized to uppercase.

### 10. `top_reasons`
- **Type**: `List[str]`
- **Description**: Explanatory human reasons (avoid ML mathematical feature parameters).
- **Validation Rule**: Must be a list of strings.

### 11. `metadata`
- **Type**: `Dict[str, Any]`
- **Description**: Detector-specific raw telemetry attributes or features.
- **Validation Rule**: Must be a dictionary.
