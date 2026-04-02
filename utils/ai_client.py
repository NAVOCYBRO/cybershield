import os
import json
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv

load_dotenv()

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

try:
    import aiohttp
    ASYNCIO_AVAILABLE = True
except ImportError:
    ASYNCIO_AVAILABLE = False


class AIMultiClient:
    def __init__(self):
        """Initialize AI client with support for multiple providers"""
        self.groq_api_key = os.getenv('GROQ_API_KEY')
        self.openrouter_api_key = os.getenv('OPENROUTER_API_KEY')
        
        self.groq_client = None
        self.openrouter_client = None
        
        self.groq_model = "qwen/qwen3-32b"
        self.openrouter_default_model = "anthropic/claude-3-haiku-20250711"
        self.openrouter_auto_model = "openrouter/auto"
        self.openrouter_model = os.getenv('OPENROUTER_MODEL', self.openrouter_default_model)
        
        self._active_provider = None
        
        if self.groq_api_key and GROQ_AVAILABLE:
            try:
                self.groq_client = Groq(api_key=self.groq_api_key)
                print(f"Groq client initialized with model: {self.groq_model}")
            except Exception as e:
                print(f"Groq initialization failed: {e}")
        
        if self.openrouter_api_key:
            self.openrouter_client = OpenRouterClient(self.openrouter_api_key)
            print(f"OpenRouter client initialized with model: {self.openrouter_model}")
        
        self._detect_active_provider()
    
    def _detect_active_provider(self):
        """Detect which provider to use based on availability"""
        if self.groq_client:
            self._active_provider = 'groq'
        elif self.openrouter_client:
            self._active_provider = 'openrouter'
        else:
            self._active_provider = None
    
    def get_status(self) -> Dict[str, Any]:
        """Get current AI client status"""
        provider = self._active_provider
        
        if provider == 'groq' and self.groq_client:
            return {
                'available': True,
                'provider': 'Groq',
                'model': self.groq_model,
                'groq_available': True,
                'openrouter_available': self.openrouter_client is not None
            }
        elif provider == 'openrouter' and self.openrouter_client:
            return {
                'available': True,
                'provider': 'OpenRouter',
                'model': self.openrouter_model,
                'groq_available': self.groq_client is not None,
                'openrouter_available': True
            }
        elif self.groq_client:
            return {
                'available': True,
                'provider': 'Groq',
                'model': self.groq_model,
                'groq_available': True,
                'openrouter_available': self.openrouter_client is not None
            }
        elif self.openrouter_client:
            return {
                'available': True,
                'provider': 'OpenRouter',
                'model': self.openrouter_model,
                'groq_available': False,
                'openrouter_available': True
            }
        else:
            return {
                'available': False,
                'provider': 'None',
                'model': None,
                'groq_available': False,
                'openrouter_available': False
            }
    
    def list_providers(self) -> List[Dict[str, Any]]:
        """List all available providers"""
        providers = []
        
        if self.groq_client:
            providers.append({
                'id': 'groq',
                'name': 'Groq',
                'model': self.groq_model,
                'available': True
            })
        else:
            providers.append({
                'id': 'groq',
                'name': 'Groq',
                'model': self.groq_model,
                'available': False,
                'error': 'API key not configured' if not self.groq_api_key else 'Unknown error'
            })
        
        if self.openrouter_client:
            providers.append({
                'id': 'openrouter',
                'name': 'OpenRouter',
                'model': self.openrouter_model,
                'available': True
            })
        else:
            providers.append({
                'id': 'openrouter',
                'name': 'OpenRouter',
                'model': self.openrouter_model,
                'available': False,
                'error': 'API key not configured' if not self.openrouter_api_key else 'Unknown error'
            })
        
        return providers
    
    def set_provider(self, provider: str) -> bool:
        """Set the active AI provider"""
        if provider == 'groq' and self.groq_client:
            self._active_provider = 'groq'
            return True
        elif provider == 'openrouter' and self.openrouter_client:
            self._active_provider = 'openrouter'
            return True
        return False
    
    def set_openrouter_model(self, model: str = 'auto') -> bool:
        """Set OpenRouter model - use 'auto' for automatic model selection"""
        if not self.openrouter_client:
            return False
        if model == 'auto':
            self.openrouter_model = self.openrouter_auto_model
            print(f"OpenRouter model set to: AUTO (automatic selection)")
        elif model == 'default':
            self.openrouter_model = self.openrouter_default_model
            print(f"OpenRouter model set to: {self.openrouter_default_model}")
        else:
            self.openrouter_model = model
            print(f"OpenRouter model set to: {model}")
        return True
    
    def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models for each provider"""
        models = {
            'groq': {
                'available': self.groq_client is not None,
                'current': self.groq_model,
                'models': ['qwen/qwen3-32b', 'qwen/qwen2.5-32b', 'meta-llama/llama-4-scout-17b-16e-instruct', 'deepseek-r1-distill-qwen-32b']
            },
            'openrouter': {
                'available': self.openrouter_client is not None,
                'current': self.openrouter_model,
                'models': ['openrouter/auto', 'anthropic/claude-3-haiku-20250711', 'google/gemini-2.0-flash-exp', 'meta-llama/llama-3.3-70b-instruct']
            }
        }
        return models
    
    def chat(self, messages: List[Dict], model: str = None, **kwargs) -> Optional[str]:
        """Send chat request to active provider"""
        if self._active_provider == 'groq' and self.groq_client:
            return self._groq_chat(messages, model or self.groq_model, **kwargs)
        elif self.openrouter_client:
            return self._openrouter_chat(messages, model or self.openrouter_model, **kwargs)
        elif self.groq_client:
            return self._groq_chat(messages, model or self.groq_model, **kwargs)
        else:
            return None
    
    def _groq_chat(self, messages: List[Dict], model: str, **kwargs) -> Optional[str]:
        """Send chat request to Groq API"""
        if not self.groq_client:
            return None
        
        try:
            response = self.groq_client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=kwargs.get('temperature', 0.7),
                max_tokens=kwargs.get('max_tokens', 2000),
                top_p=kwargs.get('top_p', 1),
                stream=False
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Groq API error: {e}")
            return None
    
    def _openrouter_chat(self, messages: List[Dict], model: str, **kwargs) -> Optional[str]:
        """Send chat request to OpenRouter API"""
        if not self.openrouter_client:
            return None
        
        try:
            return self.openrouter_client.generate_sync(
                messages=messages,
                model=model,
                temperature=kwargs.get('temperature', 0.7),
                max_tokens=kwargs.get('max_tokens', 2000)
            )
        except Exception as e:
            print(f"OpenRouter API error: {e}")
            return None


class OpenRouterClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://openrouter.ai/api/v1"
    
    async def generate_async(
        self,
        messages: List[Dict],
        model: str = "anthropic/claude-3-haiku-20250711",
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """Generate response using OpenRouter API (async)"""
        if not ASYNCIO_AVAILABLE:
            return self.generate_sync(messages, model, temperature, max_tokens)
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://cybershield.local",
            "X-Title": "CyberShield Vulnerability Scanner"
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        choices = data.get("choices", [{}])
                        if choices:
                            return choices[0].get("message", {}).get("content", "")
                    else:
                        error_text = await response.text()
                        print(f"OpenRouter error: {response.status} - {error_text}")
        except Exception as e:
            print(f"OpenRouter request failed: {e}")
        
        return None
    
    def generate_sync(
        self,
        messages: List[Dict],
        model: str = "anthropic/claude-3-haiku-20250711",
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """Generate response using OpenRouter API (sync via requests)"""
        import requests
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://cybershield.local",
            "X-Title": "CyberShield Vulnerability Scanner"
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                choices = data.get("choices", [{}])
                if choices:
                    return choices[0].get("message", {}).get("content", "")
            else:
                print(f"OpenRouter error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"OpenRouter request failed: {e}")
        
        return None


ai_client = AIMultiClient()
