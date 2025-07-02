from abc import ABC, abstractmethod
from typing import Optional, Dict
from deepeval.models import GPTModel
import json
from deepteam.guardrails.types import GuardType

class BaseDecorativeGuard(ABC):
    score: Optional[float] = None
    score_breakdown: Dict = None
    reason: Optional[str] = None
    evaluation_model: Optional[str] = None
    error: Optional[str] = None
    latency: Optional[float] = None
    guard_type: GuardType

    def __init__(self):
        self.model = GPTModel(model="gpt-4o-mini")
        self.evaluation_model = "gpt-4o-mini"

    @property
    def __name__(self):
        return "Base Decorative Guard"
    
    def guard(self, input: str = None, response: str = None, **kwargs) -> float:
        """
        Guard method - returns score between 0.0 (unsafe) and 1.0 (safe)
        """
        try:
            if response is not None:
                prompt = self._get_output_prompt(input or "", response)
            else:
                prompt = self._get_input_prompt(input)
                
            llm_response = self.model.generate(prompt)
            
            # Handle tuple response
            if isinstance(llm_response, tuple):
                llm_response = llm_response[0]
                
            return self._parse_json_response(llm_response)
            
        except Exception as e:
            self.error = str(e)
            self.score = 0.0  
            return 0.0
    
    async def a_guard(self, input: str = None, response: str = None, **kwargs) -> float:
        """
        Async guard method - returns score between 0.0 (unsafe) and 1.0 (safe)
        """
        try:
            if response is not None:
                prompt = self._get_output_prompt(input or "", response)
            else:  
                prompt = self._get_input_prompt(input)
                
            llm_response = await self.model.a_generate(prompt)
            
            # Handle tuple response
            if isinstance(llm_response, tuple):
                llm_response = llm_response[0]
                
            return self._parse_json_response(llm_response)
            
        except Exception as e:
            self.error = str(e)
            self.score = 0.0  
            return 0.0
    
    def _parse_json_response(self, response: str) -> float:
        """
        Parse JSON response from LLM to determine safety score
        Returns 1.0 if safe, 0.0 if unsafe
        """
        try:
            response_clean = response.strip()

            start_idx = response_clean.find('{')
            end_idx = response_clean.rfind('}')
            
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_str = response_clean[start_idx:end_idx + 1]
                data = json.loads(json_str)
            else:
                data = json.loads(response_clean)
            
            is_safe = False
            if "safe" in data:
                is_safe = bool(data["safe"])
            elif "is_safe" in data:
                is_safe = bool(data["is_safe"])
            elif "verdict" in data:
                verdict = str(data["verdict"]).lower()
                is_safe = verdict in ["safe", "true", "yes"]
            
            self.reason = data.get("reason", data.get("explanation", "No explanation provided"))
            self.score = 1.0 if is_safe else 0.0
            
            return self.score
                
        except (json.JSONDecodeError, KeyError, ValueError) as e:

            response_lower = response.lower().strip()
            
            unsafe_patterns = ["unsafe", "not safe", "false", "dangerous", "harmful", "violation", "breach"]
            safe_patterns = ["safe", "true", "secure", "acceptable", "compliant"]
            
            for pattern in unsafe_patterns:
                if pattern in response_lower:
                    self.reason = f"Detected as unsafe via fallback parsing (found: {pattern})"
                    self.score = 0.0
                    return 0.0
            
            for pattern in safe_patterns:
                if pattern in response_lower:
                    self.reason = f"Detected as safe via fallback parsing (found: {pattern})"
                    self.score = 1.0
                    return 1.0
            
            # Default to unsafe if completely unclear
            self.reason = f"Unclear response, defaulting to unsafe. Response: {response[:100]}..."
            self.score = 0.0
            return 0.0
    
    @abstractmethod
    def _get_input_prompt(self, input_text: str) -> str:
        """
        Get prompt for evaluating input text
        """
        pass
    
    @abstractmethod
    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        """
        Get prompt for evaluating output text
        """
        pass


class BaseGuard(BaseDecorativeGuard):
    @abstractmethod
    async def a_guard_input(self, input: str, *args, **kwargs) -> float:
        raise NotImplementedError(
            f"Async execution for {self.__class__.__name__} not supported yet."
        )

    @abstractmethod
    async def a_guard_output(
        self, input: str, output: str, *args, **kwargs
    ) -> float:
        raise NotImplementedError(
            f"Async execution for {self.__class__.__name__} not supported yet."
        )

    @property
    def __name__(self):
        return "Base Guard"
