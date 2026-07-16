import os
import json
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from .rag.query import search

# Ensure API key is configured
# Assuming the user has a .env with GEMINI_API_KEY and python-dotenv loads it in their main app
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))

# Use Gemini 1.5 Flash as requested in architecture
MODEL_NAME = "gemini-1.5-flash"

SYSTEM_PROMPT = """
You are the Hypothesis Generation Agent for Sentient-Prime, an AI-powered Cyber Resilience platform for Critical National Infrastructure (CNI).
Your task is to analyze an incoming security alert along with relevant MITRE ATT&CK context, and generate 3-4 competing hypotheses that explain the observed behavior.

CRITICAL RULES:
1. You must output exactly 3 or 4 hypotheses.
2. At least one hypothesis MUST be benign (is_benign: true), acting as a false positive filter (e.g., "Legitimate administrator locked out").
3. Your output MUST be valid, raw JSON array of objects, and nothing else. No markdown formatting, no code blocks (e.g., do not wrap in ```json).

Output Schema Example:
[
  {
    "hypothesis": "APT41 initial credential access attempt",
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "credential-access",
    "confidence": 0.62,
    "reasoning": "Single source IP targeting SSH at high frequency matches APT41 TTPs",
    "is_benign": false
  },
  {
    "hypothesis": "Legitimate administrator locked out",
    "technique_id": null,
    "technique_name": null,
    "tactic": null,
    "confidence": 0.09,
    "reasoning": "Source IP is internal subnet, 3AM timing unusual but possible",
    "is_benign": true
  }
]
"""

def generate_hypotheses(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Block 1: Generates hypotheses based on the Common Evidence Object.
    """
    # 1. Extract context from evidence to form a search query
    # If the evidence provides a description or network class, use it.
    description = ""
    if "network" in evidence and "class" in evidence["network"]:
        description += f"Network anomaly: {evidence['network']['class']}. "
    if "endpoint" in evidence and "sigma_matches" in evidence["endpoint"]:
        description += f"Endpoint signals: {', '.join(evidence['endpoint']['sigma_matches'])}. "
    
    # Fallback if no specific text is found (using the incident ID or raw dump)
    if not description:
        description = json.dumps(evidence)
        
    # 2. Retrieve MITRE ATT&CK context via FAISS RAG
    try:
        rag_results = search(description, top_k=3)
        rag_context = "\n".join([f"- {r['technique_id']}: {r['name']} - {r['description'][:200]}..." for r in rag_results])
    except Exception as e:
        rag_context = f"Failed to retrieve RAG context: {e}"

    # 3. Construct prompt
    user_prompt = f"""
    Incoming Common Evidence Object (Alert):
    {json.dumps(evidence, indent=2)}
    
    Relevant MITRE ATT&CK Context from RAG:
    {rag_context}
    
    Generate the hypotheses JSON array now.
    """
    
    # 4. Call Gemini Flash
    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=SYSTEM_PROMPT
    )
    
    try:
        response = model.generate_content(user_prompt)
        text_output = response.text
        
        # 5. Parse output robustly (strip markdown if present)
        text_output = text_output.replace("```json", "").replace("```", "").strip()
        
        hypotheses = json.loads(text_output)
        
        # Ensure it's a list
        if isinstance(hypotheses, dict):
            hypotheses = [hypotheses]
            
        return hypotheses
        
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from Gemini: {e}")
        print(f"Raw output: {response.text}")
        # Fallback benign hypothesis
        return [{
            "hypothesis": "Parsing failed - assuming benign until reviewed",
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "confidence": 0.1,
            "reasoning": f"System error generating hypotheses: {e}",
            "is_benign": True
        }]
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        raise

class HypothesisAgent:
    def __init__(self):
        from .base_agent import BaseAgent
        from .prompts import HYPOTHESIS_PROMPT, HypothesisList
        self.agent = BaseAgent(
            system_instruction=HYPOTHESIS_PROMPT,
            response_schema=HypothesisList
        )
        
    def run(self, story: dict, context: Optional[Any] = None) -> dict:
        import json
        context_str = ""
        if context:
            context_dict = context.to_dict() if hasattr(context, "to_dict") else context
            context_str = f"\nSECURITY CONTEXT:\n{json.dumps(context_dict, indent=2)}"
            
        prompt = f"""
        Based on the provided cross-domain incident story and security context, generate the competing hypotheses.
        
        INCIDENT STORY:
        {json.dumps(story, indent=2)}
        {context_str}
        """
        return self.agent.run(prompt)
