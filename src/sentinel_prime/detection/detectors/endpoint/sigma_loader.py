import os
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    severity: str
    tags: List[str] = field(default_factory=list)
    detection: Dict[str, Any] = field(default_factory=dict)
    raw_rule: Dict[str, Any] = field(default_factory=dict)

    @property
    def mitre_tactics(self) -> List[str]:
        tactics = []
        for tag in self.tags:
            if tag.startswith("attack."):
                parts = tag.split(".")
                if len(parts) > 1 and not parts[1].startswith("t"):
                    tactics.append(parts[1])
        return tactics

    @property
    def mitre_techniques(self) -> List[str]:
        techniques = []
        for tag in self.tags:
            if tag.startswith("attack.t"):
                parts = tag.split(".")
                if len(parts) > 1:
                    # e.g. attack.t1059.001 -> T1059.001
                    tech_id = parts[1].upper()
                    if len(parts) > 2:
                        tech_id += f".{parts[2]}"
                    techniques.append(tech_id)
        return techniques

def load_sigma_rules(directory_path: str) -> List[SigmaRule]:
    """
    Recursively scans the directory for YAML rules and parses them.
    """
    dir_path = Path(directory_path)
    if not dir_path.exists():
        logger.warning(f"Sigma directory does not exist: {directory_path}")
        return []

    rules = []
    yaml_files = list(dir_path.rglob("*.yaml")) + list(dir_path.rglob("*.yml"))
    logger.info(f"Discovered {len(yaml_files)} potential Sigma rule files.")

    for f_path in yaml_files:
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Parse YAML documents (supporting multi-document files)
                docs = yaml.safe_load_all(content)
                for doc in docs:
                    if not doc or not isinstance(doc, dict):
                        continue
                    
                    # Validate basic Sigma fields
                    title = doc.get("title")
                    detection = doc.get("detection")
                    if not title or not detection:
                        logger.warning(f"Ignoring malformed rule in {f_path.name}: missing title or detection block.")
                        continue
                    
                    rule_id = doc.get("id") or str(hash(title))
                    description = doc.get("description") or ""
                    severity = doc.get("level") or "medium"
                    tags = doc.get("tags") or []

                    rule = SigmaRule(
                        rule_id=str(rule_id),
                        title=str(title),
                        description=str(description),
                        severity=str(severity),
                        tags=[str(t) for t in tags],
                        detection=detection,
                        raw_rule=doc
                    )
                    rules.append(rule)
        except Exception as e:
            logger.warning(f"Failed to load or parse Sigma rule file {f_path}: {e}")
            
    logger.info(f"Successfully loaded {len(rules)} Sigma rules.")
    return rules
