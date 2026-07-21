import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict

# Define a custom demonstration logger
class DemoLogger:
    def __init__(self, name: str = "DemoPipeline"):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            # Force UTF-8 on Windows
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
                
            formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            
    def _banner(self, title: str, char: str = "="):
        self.logger.info(f"\n{char * 70}\n  {title}\n{char * 70}")
        
    def step(self, title: str):
        self._banner(title, char="-")

    def trace(self, component: str, details: str):
        self.logger.info(f"[{component.upper()}] {details}")
        
    def info(self, msg: str):
        self.logger.info(msg)

    def success(self, msg: str):
        self.logger.info(f"✅ {msg}")
        
    def warning(self, msg: str):
        self.logger.warning(f"⚠️ {msg}")
        
    def error(self, msg: str):
        self.logger.error(f"❌ {msg}")

    def log_ai_reasoning(self, agent_name: str, input_data: Any, output_data: Any, latency: float, confidence: float = None):
        """Format AI traces clearly."""
        self.trace("AI_EXECUTION", f"Agent: {agent_name} | Latency: {latency:.2f}s")
        if confidence is not None:
            self.trace("AI_CONFIDENCE", f"{confidence:.2f}")
        
        try:
            formatted_in = json.dumps(input_data, indent=2) if isinstance(input_data, (dict, list)) else str(input_data)
            formatted_out = json.dumps(output_data, indent=2) if isinstance(output_data, (dict, list)) else str(output_data)
        except Exception:
            formatted_in = str(input_data)
            formatted_out = str(output_data)

        # Print inputs and outputs concisely for the demo
        if len(formatted_in.splitlines()) > 10:
            formatted_in = "\n".join(formatted_in.splitlines()[:10]) + "\n  ... (truncated)"
            
        print(f"\n  [INPUT] ->\n  {formatted_in}\n")
        print(f"  [OUTPUT] <-\n  {formatted_out}\n")

    def log_soar_decision(self, playbook: str, action: str, entity: str):
        self.trace("SOAR", f"Executed Playbook: {playbook}")
        self.trace("SOAR", f"Action: {action} on {entity}")

    def log_honeypot_event(self, decoy_id: str, action: str):
        self.trace("HONEYPOT", f"Decoy [{decoy_id}]: {action}")

    def log_graph_update(self, nodes_added: int, edges_added: int):
        self.trace("CYBER_GRAPH", f"Updated! Added {nodes_added} nodes, {edges_added} edges.")

demo_logger = DemoLogger()
