# OT Specialist Evidence Schema Reference

Defines the structure for the `OTEvidence` payload created by the OT Specialist.

## Evidence JSON Example

```json
{
  "detector": "ot",
  "entity": "CNI-Process-PLC",
  "timestamp": "2019-09-11 20:10:00",
  "window_start": "2019-09-11 20:09:00",
  "window_end": "2019-09-11 20:10:00",
  "risk_score": 0.82,
  "confidence": 0.85,
  "severity": "HIGH",
  "anomaly_score": 0.82,
  "attack_probability": 0.0,
  "top_shifted_variables": [
    "P1_PV01",
    "P2_PV02"
  ],
  "behaviour_summary": "Industrial process anomaly score = 0.82 (HIGH severity). Top shifted variables: P1_PV01, P2_PV02.",
  "top_reasons": [
    "Sensor flatline detected: P1_PV01 remained constant for 60s"
  ],
  "raw_prediction": 0.82,
  "schema_version": "v2.1"
}
```

## Fields Details

| Field | Type | Allowed Values | Description |
|---|---|---|---|
| `detector` | `string` | `"ot"` | Specialist detector identifier. |
| `entity` | `string` | e.g. `"CNI-Process-PLC"` | Target PLC or process loop being monitored. |
| `timestamp` | `string` | ISO format or YYYY-MM-DD HH:MM:SS | Time of evidence generation. |
| `window_start` | `string` | YYYY-MM-DD HH:MM:SS | Start of the 60-second process window. |
| `window_end` | `string` | YYYY-MM-DD HH:MM:SS | End of the 60-second process window. |
| `risk_score` | `float` | `0.0` to `1.0` | Combined threat score from anomaly calibration and supervised classifier. |
| `confidence` | `float` | `0.0` to `1.0` | Statistical confidence of the assessment. |
| `severity` | `string` | `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"` | Severity categorization of the anomaly. |
| `anomaly_score` | `float` | `0.0` to `1.0` | Calibrated anomaly score from the Isolation Forest. |
| `attack_probability`| `float` | `0.0` to `1.0` | Attack probability from the LightGBM classifier. |
| `top_shifted_variables`| `array of strings` | List of process variable names | Top 5 variables showing the largest deviation. |
| `behaviour_summary` | `string` | Descriptive text | Short summary text outlining threats and shifted metrics. |
| `top_reasons` | `array of strings` | List of human-readable statements | Diagnostic justifications for the SOC analyst. |
| `raw_prediction` | `float` | float | Raw unscaled output. |
| `schema_version` | `string` | `"v2.1"` | Schema schema versioning identifier. |
