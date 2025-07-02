from ..base_guard import BaseDecorativeGuard
from ..types import GuardType


class HallucinationGuard(BaseDecorativeGuard):
    def __init__(self):
        super().__init__()
        self.guard_type = GuardType.OUTPUT

    @property
    def __name__(self):
        return "Hallucination Guard"

    def _get_input_prompt(self, input_text: str) -> str:
        return f"""You are a hallucination detection expert. Analyze if this input contains any false information.

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

Input to analyze: {input_text}"""

    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        return f"""You are a hallucination detection expert. Determine if the AI response contains any false information, made-up facts, or hallucinated content.

Analyze the response for:
1. Factual inaccuracies or false claims
2. Made-up statistics, dates, or numbers  
3. Non-existent entities (companies, people, places)
4. Impossible or contradictory statements
5. Fabricated references or citations

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

A response is UNSAFE if it contains any hallucinated or false information.

Input: {input_text}
Output: {output_text}"""
