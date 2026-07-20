import json
from google import genai
from google.genai import types
from pydantic import BaseModel
from typing import Type, Any, Dict
from sentinel_prime.core.config_manager import config
from sentinel_prime.ai.agents.rate_limiter import rate_limiter

def get_gemini_client(api_key: str):
    if not api_key:
        raise ValueError("API key is missing.")
    return genai.Client(api_key=api_key)

class BaseAgent:
    def __init__(self, system_instruction: str, response_schema: Type[BaseModel], api_key: str):
        self.system_instruction = system_instruction
        self.response_schema = response_schema
        self.api_key = api_key
        self.client = get_gemini_client(self.api_key)
        
    def run(self, prompt: str) -> Dict[str, Any]:
        """Runs the agent with the given prompt and returns a structured JSON dictionary."""
        
        # Enforce rate limiting based on the specific API key
        rate_limiter.wait(self.api_key)
        
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0, # Maximum determinism
            response_mime_type="application/json",
            response_schema=self.response_schema
        )
        
        try:
            response = self.client.models.generate_content(
                model='gemini-3.1-flash-lite',
                contents=prompt,
                config=config
            )
            
            # The response text should be valid JSON matching the schema
            return json.loads(response.text)
            
        except Exception as e:
            print(f"Agent Execution Error: {e}")
            raise
