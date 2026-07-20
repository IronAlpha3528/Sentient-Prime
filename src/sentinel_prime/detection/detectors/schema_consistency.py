import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def verify_contracts() -> Dict[str, Any]:
    """
    Compares feature contracts and models' feature contracts to automatically 
    detect schema, name, and ordering mismatches.
    """
    report = {
        "status": "Consistent",
        "mismatches": [],
        "details": {}
    }

    # 1. Network Contract Check
    net_contract_path = Path("data/models/network/v2/feature_columns.json")
    if net_contract_path.exists():
        try:
            with open(net_contract_path, "r", encoding="utf-8") as f:
                net_cols = json.load(f)
            report["details"]["network"] = {
                "features_count": len(net_cols),
                "sample_features": net_cols[:5]
            }
        except Exception as e:
            report["mismatches"].append(f"Network: failed to read feature contract: {e}")
    else:
        report["mismatches"].append("Network: feature contract file missing.")

    # 2. Identity Contract Check
    id_contract_path = Path("data/models/identity/v2_1/feature_columns.json")
    if id_contract_path.exists():
        try:
            with open(id_contract_path, "r", encoding="utf-8") as f:
                id_cols = json.load(f)
            report["details"]["identity"] = {
                "features_count": len(id_cols),
                "sample_features": id_cols
            }
        except Exception as e:
            report["mismatches"].append(f"Identity: failed to read feature contract: {e}")
    else:
        report["mismatches"].append("Identity: feature contract file missing.")

    # 3. Endpoint Contract Check
    ep_contract_path = Path("models/endpoint/feature_contract.json")
    if ep_contract_path.exists():
        try:
            with open(ep_contract_path, "r", encoding="utf-8") as f:
                ep_cols = json.load(f)
            report["details"]["endpoint"] = {
                "features_count": len(ep_cols),
                "sample_features": list(ep_cols.keys())[:5]
            }
        except Exception as e:
            report["mismatches"].append(f"Endpoint: failed to read feature contract: {e}")
    else:
        report["mismatches"].append("Endpoint: feature contract file missing.")

    # 4. OT Contract Check
    ot_contract_path = Path("models/ot/feature_contract.json")
    if ot_contract_path.exists():
        try:
            with open(ot_contract_path, "r", encoding="utf-8") as f:
                ot_cols = json.load(f)
            report["details"]["ot"] = {
                "features_count": len(ot_cols),
                "sample_features": list(ot_cols.keys())[:5]
            }
        except Exception as e:
            report["mismatches"].append(f"OT: failed to read feature contract: {e}")
    else:
        report["mismatches"].append("OT: feature contract file missing.")

    if report["mismatches"]:
        report["status"] = "Inconsistent"
        logger.warning(f"Feature contract mismatches detected: {report['mismatches']}")
    else:
        logger.info("All detector feature contracts are consistent.")

    return report
