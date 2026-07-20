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
    def __init__(self, system_instruction: str, response_schema: Type[BaseModel], api_key: str, fallback_api_key: str = None):
        self.system_instruction = system_instruction
        self.response_schema = response_schema
        self.api_key = api_key
        self.fallback_api_key = fallback_api_key or config.GEMINI_API_KEY
        self.client = get_gemini_client(self.api_key)
        self.fallback_client = get_gemini_client(self.fallback_api_key) if self.fallback_api_key else None
        
    def _generate(self, client, prompt: str, gen_config) -> Dict[str, Any]:
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config=gen_config
        )
        return json.loads(response.text)

    def run(self, prompt: str) -> Dict[str, Any]:
        """Runs the agent with the given prompt and returns a structured JSON dictionary."""
        rate_limiter.wait(self.api_key)
        
        gen_config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0, # Maximum determinism
            response_mime_type="application/json",
            response_schema=self.response_schema
        )
        
        try:
            return self._generate(self.client, prompt, gen_config)
            
        except Exception as e:
            error_str = str(e).lower()
            if "429" in error_str or "quota" in error_str:
                if self.fallback_api_key and self.fallback_api_key != self.api_key:
                    print(f"Agent specific key exhausted (429). Falling back to default key...")
                    rate_limiter.wait(self.fallback_api_key)
                    try:
                        return self._generate(self.fallback_client, prompt, gen_config)
                    except Exception as fallback_e:
                        print(f"Fallback Execution Error: {fallback_e}")
                        raise fallback_e
                
                # Single-key automatic retry with backoff
                import re
                import time
                match = re.search(r"retry in ([\d\.]+)s", error_str)
                wait_time = float(match.group(1)) + 2 if match else 20.0
                print(f"Quota exhausted (429). Sleeping for {wait_time:.1f}s before retrying...")
                time.sleep(wait_time)
                try:
                    return self._generate(self.client, prompt, gen_config)
                except Exception as retry_e:
                    print(f"Retry Execution Error: {retry_e}")
                    raise retry_e
            
            print(f"Agent Execution Error: {e}")
            raise
