from typing import List, Dict, Any, Optional
import time
import asyncio
import random

from deepteam.guardrails.base_guard import BaseGuard
from deepteam.guardrails.types import GuardType


class GuardResult:
    def __init__(self, guard_results: Dict[str, Any]):
        self.guard_results = guard_results
        # Calculate breached automatically from guard results
        self.breached = any(
            not result.get("safe", False) 
            for result in guard_results.values()
        )


class Guardrails:
    """
    Open-source guardrails system for production LLM safety.
    Fast binary classification to guard inputs and outputs.
    """
    
    def __init__(
        self, 
        input_guards: List[BaseGuard],
        output_guards: List[BaseGuard],
        default_evaluation_model: Optional[str] = None,
        sample_rate: Optional[float] = None
    ):
        """
        Initialize Guardrails with separate input and output guards.
        
        Args:
            input_guards: List of guards to check inputs before they reach your LLM
            output_guards: List of guards to check outputs before they reach your users
            default_evaluation_model: Default OpenAI model for guards without explicit model
            sample_rate: Fraction of requests to process (0.0 to 1.0). If None, processes all requests
        """
        self.input_guards = input_guards
        self.output_guards = output_guards
        self.default_evaluation_model = default_evaluation_model
        
        # Validate and set sample rate
        if sample_rate is not None:
            if not 0.0 <= sample_rate <= 1.0:
                raise ValueError("sample_rate must be between 0.0 and 1.0")
        self.sample_rate = sample_rate
        
        # Apply default model to guards that don't have explicit models
        if default_evaluation_model:
            self._apply_default_model_to_guards()

    def _apply_default_model_to_guards(self):
        """Apply default evaluation model to guards that don't have explicit models"""
        all_guards = self.input_guards + self.output_guards
        for guard in all_guards:
            # Only update if guard doesn't already have a specific model configured
            if guard.evaluation_model == "gpt-4o":  # Default from BaseGuard
                guard.__init__(evaluation_model=self.default_evaluation_model)

    def _should_process_request(self) -> bool:
        """Determine if request should be processed based on sample rate"""
        if self.sample_rate is None:
            return True
        return random.random() < self.sample_rate

    def guard_input(self, input: str) -> GuardResult:
        """
        Guard an input string using all configured input guards.
        Returns GuardResult with binary safe/unsafe classification.
        """
        if len(self.input_guards) == 0:
            raise TypeError(
                "Guardrails cannot guard inputs when no input_guards are provided."
            )

        # Check sample rate
        if not self._should_process_request():
            # Return safe result without processing
            return GuardResult(guard_results={})

        guard_results = {}
        
        for guard in self.input_guards:
            start_time = time.time()
            try:
                is_safe = guard.guard_input(input)
                latency = time.time() - start_time
                
                guard_results[guard.__name__] = {
                    "safe": is_safe,
                    "latency": latency,
                    "reason": getattr(guard, "reason", None),
                    "score": getattr(guard, "score", None)
                }
                    
            except Exception as e:
                guard_results[guard.__name__] = {
                    "safe": False,
                    "latency": time.time() - start_time,
                    "error": str(e)
                }

        return GuardResult(guard_results=guard_results)

    def guard_output(self, input: str, output: str) -> GuardResult:
        """
        Guard an output string using all configured output guards.
        Returns GuardResult with binary safe/unsafe classification.
        """
        if len(self.output_guards) == 0:
            raise TypeError(
                "Guardrails cannot guard outputs when no output_guards are provided."
            )

        # Check sample rate
        if not self._should_process_request():
            # Return safe result without processing
            return GuardResult(guard_results={})

        guard_results = {}
        
        for guard in self.output_guards:
            start_time = time.time()
            try:
                is_safe = guard.guard_output(input, output)
                latency = time.time() - start_time
                
                guard_results[guard.__name__] = {
                    "safe": is_safe,
                    "latency": latency,
                    "reason": getattr(guard, "reason", None),
                    "score": getattr(guard, "score", None)
                }
                    
            except Exception as e:
                guard_results[guard.__name__] = {
                    "safe": False,
                    "latency": time.time() - start_time,
                    "error": str(e)
                }

        return GuardResult(guard_results=guard_results)

    async def a_guard_input(self, input: str) -> GuardResult:
        """
        Async version of guard_input for better performance.
        """
        if len(self.input_guards) == 0:
            raise TypeError(
                "Guardrails cannot guard inputs when no input_guards are provided."
            )

        # Check sample rate
        if not self._should_process_request():
            # Return safe result without processing
            return GuardResult(guard_results={})

        tasks = []
        for guard in self.input_guards:
            task = asyncio.create_task(self._async_guard_input_single(guard, input))
            tasks.append((guard, task))

        guard_results = {}

        for guard, task in tasks:
            try:
                result = await task
                guard_results[guard.__name__] = result
            except Exception as e:
                guard_results[guard.__name__] = {
                    "safe": False,
                    "error": str(e)
                }

        return GuardResult(guard_results=guard_results)

    async def a_guard_output(self, input: str, output: str) -> GuardResult:
        """
        Async version of guard_output for better performance.
        """
        if len(self.output_guards) == 0:
            raise TypeError(
                "Guardrails cannot guard outputs when no output_guards are provided."
            )

        # Check sample rate
        if not self._should_process_request():
            # Return safe result without processing
            return GuardResult(guard_results={})

        tasks = []
        for guard in self.output_guards:
            task = asyncio.create_task(self._async_guard_output_single(guard, input, output))
            tasks.append((guard, task))

        guard_results = {}

        for guard, task in tasks:
            try:
                result = await task
                guard_results[guard.__name__] = result
            except Exception as e:
                guard_results[guard.__name__] = {
                    "safe": False,
                    "error": str(e)
                }

        return GuardResult(guard_results=guard_results)

    async def _async_guard_input_single(self, guard: BaseGuard, input: str):
        """Helper method for async input guarding."""
        start_time = time.time()
        is_safe = await guard.a_guard_input(input)
        latency = time.time() - start_time
        
        return {
            "safe": is_safe,
            "latency": latency,
            "reason": getattr(guard, "reason", None),
            "score": getattr(guard, "score", None)
        }

    async def _async_guard_output_single(self, guard: BaseGuard, input: str, output: str):
        """Helper method for async output guarding."""
        start_time = time.time()
        is_safe = await guard.a_guard_output(input, output)
        latency = time.time() - start_time
        
        return {
            "safe": is_safe,
            "latency": latency,
            "reason": getattr(guard, "reason", None),
            "score": getattr(guard, "score", None)
        }
