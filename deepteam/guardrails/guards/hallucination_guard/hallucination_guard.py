from typing import Optional, Union

from deepeval.models import DeepEvalBaseLLM
from deepteam.guardrails.guards.base_guard import BaseGuard
from deepteam.guardrails.guards.hallucination_guard.template import (
    HallucinationGuardTemplate,
)
from deepteam.guardrails.types import GuardType


class HallucinationGuard(BaseGuard):
    def __init__(self, model: Optional[Union[str, DeepEvalBaseLLM]] = None):
        super().__init__(model=model)

    @property
    def __name__(self):
        return "Hallucination Guard"

    def guard_input(self, input: str) -> str:
        guard_prompt = HallucinationGuardTemplate.judge_input_prompt(input_text=input)
        return self._guard(guard_prompt=guard_prompt)

    def guard_output(self, input: str, output: str) -> str:
        guard_prompt = HallucinationGuardTemplate.judge_output_prompt(
            input_text=input, output_text=output
        )
        return self._guard(guard_prompt=guard_prompt)

    async def a_guard_input(self, input: str) -> str:
        guard_prompt = HallucinationGuardTemplate.judge_input_prompt(input_text=input)
        return await self.a_guard(guard_prompt=guard_prompt)

    async def a_guard_output(self, input: str, output: str) -> str:
        guard_prompt = HallucinationGuardTemplate.judge_output_prompt(
            input_text=input, output_text=output
        )
        return await self.a_guard(guard_prompt=guard_prompt)
