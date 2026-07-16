import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Base path for templates relative to this file
TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "simulation" / "honeypots" / "templates"
DEPLOY_DIR = Path("data") / "deployed_decoys"

class DeployDecoyAction:
    """
    SOAR Action to deploy graph-guided decoys (Honeytokens / Conpot templates)
    based on the AI Deception Agent's strategy.
    """
    
    def __init__(self):
        self.templates_dir = TEMPLATES_DIR
        self.deploy_dir = DEPLOY_DIR
        
        # Ensure deploy directory exists
        self.deploy_dir.mkdir(parents=True, exist_ok=True)
        
    def execute(self, strategy: Dict[str, Any], target_host: str = "unknown-host") -> Dict[str, Any]:
        """
        Executes the decoy deployment.
        
        :param strategy: The deception strategy output from the Deception Agent
        :param target_host: The host to deploy the decoy to
        :return: Result dictionary
        """
        logger.info(f"Initiating decoy deployment on {target_host}")
        
        decoy_type = strategy.get("decoy_type", "db_credentials").lower()
        
        # Map strategy to template file
        template_file = f"{decoy_type}.template"
        template_path = self.templates_dir / template_file
        
        if not template_path.exists():
            # Fallback to a default template if specific one isn't found
            logger.warning(f"Template {template_file} not found. Falling back to db_credentials.template")
            template_file = "db_credentials.template"
            template_path = self.templates_dir / template_file
            
            if not template_path.exists():
                return {
                    "status": "failed",
                    "reason": f"No templates available in {self.templates_dir}",
                    "host": target_host
                }

        try:
            # Read template
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()
                
            # Simulate deployment by writing to the deployment directory
            deploy_name = f"{target_host}_{template_file.replace('.template', '.deployed')}"
            deploy_path = self.deploy_dir / deploy_name
            
            with open(deploy_path, "w", encoding="utf-8") as f:
                # We could inject canary token URLs here in a real scenario
                f.write(content)
                
            logger.info(f"Successfully deployed {decoy_type} decoy to {target_host} at {deploy_path}")
            
            return {
                "status": "success",
                "decoy_type": decoy_type,
                "host": target_host,
                "deployed_path": str(deploy_path),
                "strategy_used": strategy.get("rationale", "Automated SOAR deployment")
            }
            
        except Exception as e:
            logger.error(f"Failed to deploy decoy: {e}")
            return {
                "status": "error",
                "reason": str(e),
                "host": target_host
            }

if __name__ == "__main__":
    # Test the deployment
    logging.basicConfig(level=logging.INFO)
    action = DeployDecoyAction()
    
    mock_strategy = {
        "decoy_type": "vpn_config",
        "rationale": "Attacker is seeking lateral movement via VPN profiles"
    }
    
    result = action.execute(mock_strategy, target_host="prod-db-01")
    print(result)
