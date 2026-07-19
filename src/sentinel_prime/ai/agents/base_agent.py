import json
from google import genai
from google.genai import types
from pydantic import BaseModel
from typing import Type, Any, Dict
from sentinel_prime.core.config_manager import config

def get_gemini_client():
    api_key = config.GEMINI_API_KEY
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is missing. Please set it in your .env file or environment.")
    return genai.Client(api_key=api_key)

class BaseAgent:
    def __init__(self, system_instruction: str, response_schema: Type[BaseModel]):
        self.system_instruction = system_instruction
        self.response_schema = response_schema
        self.client = get_gemini_client()
        
    def run(self, prompt: str) -> Dict[str, Any]:
        """Runs the agent with the given prompt and returns a structured JSON dictionary."""
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
