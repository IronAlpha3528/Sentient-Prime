import logging
from typing import Dict, Any, List, Optional, Union
from detectors.endpoint.schemas import EndpointEvent
from detectors.endpoint.sigma_loader import SigmaRule
from detectors.endpoint.field_mapper import FIELD_ALIASES

logger = logging.getLogger(__name__)

def get_field_value_from_event(event: EndpointEvent, field_name: str) -> Optional[Any]:
    raw = event.raw_event
    
    # 1. Direct case-insensitive match in raw_event keys
    for k, v in raw.items():
        if k.lower() == field_name.lower():
            return v

    # 2. Match via alias maps
    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias.lower() == field_name.lower():
                val = getattr(event, canonical, None)
                if val is not None:
                    return val
    return None

def evaluate_value_match(event_val: Any, rule_val: Any, modifier: Optional[str]) -> bool:
    if event_val is None:
        return False

    event_val_str = str(event_val).lower()
    
    # If the rule value is a list, match if any item matches
    if isinstance(rule_val, list):
        return any(evaluate_value_match(event_val, item, modifier) for item in rule_val)

    rule_val_str = str(rule_val).lower()

    if modifier == "contains":
        return rule_val_str in event_val_str
    elif modifier == "endswith":
        return event_val_str.endswith(rule_val_str)
    elif modifier == "startswith":
        return event_val_str.startswith(rule_val_str)
    else:
        # Exact match (default)
        return event_val_str == rule_val_str

def evaluate_selector(event: EndpointEvent, selector_block: Any) -> bool:
    """
    Evaluates a single selector dictionary. All field matches must be True (AND).
    """
    if not isinstance(selector_block, dict):
        return False

    for key_modifier, rule_val in selector_block.items():
        # Parse key and modifier (e.g. ParentImage|endswith)
        if "|" in key_modifier:
            parts = key_modifier.split("|")
            field_name = parts[0]
            modifier = parts[1]
        else:
            field_name = key_modifier
            modifier = None

        event_val = get_field_value_from_event(event, field_name)
        if not evaluate_value_match(event_val, rule_val, modifier):
            return False

    return True

def evaluate_condition_safely(condition_str: str, selector_results: Dict[str, bool]) -> bool:
    """
    Parses and evaluates simple Sigma condition strings safely without eval().
    Supports:
      - 'selection'
      - 'selection and not filter'
      - 'any of selection*' / 'any of selection'
      - 'all of selection*' / 'all of selection'
    """
    cond = condition_str.strip().lower()
    
    # Simple selection match
    if cond in selector_results:
        return selector_results[cond]

    # any of / all of logic
    if cond.startswith("any of "):
        prefix = cond.replace("any of ", "").replace("*", "").strip()
        return any(v for k, v in selector_results.items() if k.lower().startswith(prefix))

    if cond.startswith("all of "):
        prefix = cond.replace("all of ", "").replace("*", "").strip()
        matching_selectors = [v for k, v in selector_results.items() if k.lower().startswith(prefix)]
        return all(matching_selectors) if matching_selectors else False

    # selection and not filter logic
    if " and not " in cond:
        parts = cond.split(" and not ")
        if len(parts) == 2:
            left = parts[0].strip()
            right = parts[1].strip()
            left_val = selector_results.get(left, False)
            right_val = selector_results.get(right, False)
            return left_val and not right_val

    # Default fallback: check if first word is a matched selector
    words = cond.split()
    if words and words[0] in selector_results:
        return selector_results[words[0]]

    return False

class SigmaEngine:
    def __init__(self, rules: List[SigmaRule]):
        self.rules = rules

    def match_event(self, event: EndpointEvent) -> List[Dict[str, Any]]:
        """
        Evaluates the event against all Sigma rules.
        Returns a list of matched rule descriptors.
        """
        matches = []
        
        for rule in self.rules:
            try:
                detection = rule.detection
                condition = detection.get("condition")
                if not condition:
                    continue

                # 1. Evaluate all selectors in the rule detection block
                selector_results = {}
                for name, block in detection.items():
                    if name != "condition":
                        selector_results[name] = evaluate_selector(event, block)

                # 2. Evaluate condition
                is_matched = evaluate_condition_safely(str(condition), selector_results)
                
                if is_matched:
                    # Gather matched field details
                    matched_fields = []
                    matched_values = []
                    for name, block in detection.items():
                        if name != "condition" and selector_results.get(name):
                            if isinstance(block, dict):
                                for km in block.keys():
                                    f_name = km.split("|")[0]
                                    matched_fields.append(f_name)
                                    val = get_field_value_from_event(event, f_name)
                                    matched_values.append(str(val) if val is not None else "")

                    matches.append({
                        "rule_id": rule.rule_id,
                        "rule_name": rule.title,
                        "severity": rule.severity,
                        "mitre_tactics": rule.mitre_tactics,
                        "mitre_techniques": rule.mitre_techniques,
                        "matched_fields": matched_fields,
                        "matched_values": matched_values,
                        "confidence": 0.85 if rule.severity == "high" else 0.60
                    })
            except Exception as e:
                # Log error and continue on other rules
                logger.error(f"Error evaluating rule '{rule.title}': {e}")
                continue

        return matches
