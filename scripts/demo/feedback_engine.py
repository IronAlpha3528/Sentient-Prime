"""Feedback Engine to simulate closed-loop graph and context updates."""

import time
from .demo_logger import demo_logger

class FeedbackEngine:
    def __init__(self):
        self.iteration = 0

    def process_feedback_loop(self, soar_result: dict, original_event: dict) -> dict:
        """
        Simulate the feedback process where the Cyber Graph and Evidence Bus
        are updated after a SOAR action, producing new context for a second AI evaluation.
        """
        demo_logger.step("CLOSED-LOOP FEEDBACK INITIATED")
        
        # 1. Evidence Publication
        demo_logger.trace("EVIDENCE_STREAM", f"Publishing verified incident outcomes for {original_event['entity_id']}...")
        time.sleep(0.5)
        
        # 2. Cyber Knowledge Graph Update
        action = soar_result.get("decision", "NONE")
        demo_logger.log_graph_update(nodes_added=2, edges_added=3)
        time.sleep(0.5)
        
        # 3. Generating new synthetic context
        demo_logger.trace("CONTEXT_BUILDER", "Refreshing context based on new graph topology...")
        time.sleep(0.5)
        
        self.iteration += 1
        demo_logger.success("Feedback loop complete. System context updated.")
        
        # Return a simulated "updated event" with more context
        updated_event = dict(original_event)
        updated_event["feedback_iteration"] = self.iteration
        updated_event["post_action_context"] = f"Action '{action}' was executed. Monitoring for circumvention."
        
        return updated_event
