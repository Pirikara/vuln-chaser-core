import os
import time
import httpx
import json
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class OpenRouterClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.base_url = "https://openrouter.ai/api/v1"
        self.model = os.getenv("OPENROUTER_MODEL", "google/gemma-3-27b-it:free")
        
        if not self.api_key:
            raise ValueError("OpenRouter API key is required")
    
    async def chat_completion(self, messages: list, **kwargs) -> Dict[str, Any]:
        """Send chat completion request to OpenRouter"""
        start_time = time.time()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 2000),
            "temperature": kwargs.get("temperature", 0.1),
            "top_p": kwargs.get("top_p", 0.9),
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://vuln-chaser.com",
            "X-Title": "VulnChaser-Core"
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )
                response.raise_for_status()
                
                result = response.json()
                end_time = time.time()
                
                # Calculate cost (approximate)
                usage = result.get("usage", {})
                cost = self._calculate_cost(usage)
                
                return {
                    "content": result["choices"][0]["message"]["content"],
                    "usage": usage,
                    "cost_usd": cost,
                    "response_time_ms": int((end_time - start_time) * 1000),
                    "model": self.model
                }
                
        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"OpenRouter request failed: {str(e)}")
            raise
    
    def _calculate_cost(self, usage: Dict[str, Any]) -> float:
        """Calculate approximate cost based on usage"""
        # Google Gemma 3 27B is free, but we track as if it had cost
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        
        # Hypothetical pricing for tracking purposes
        prompt_cost = prompt_tokens * 0.0001 / 1000  # $0.0001 per 1K tokens
        completion_cost = completion_tokens * 0.0002 / 1000  # $0.0002 per 1K tokens
        
        return prompt_cost + completion_cost
    
    async def health_check(self) -> bool:
        """Check if OpenRouter API is accessible"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"}
                )
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"OpenRouter health check failed: {e}")
            return False